//! The planner (SHA-250): turns assessments into the plan `rotate plan`
//! prints and `rotate apply` (SHA-254) carries out (FR11 to FR13).
//!
//! Building a plan calls only `Consumer::find`, on top of the read-only
//! `check_valid` and `describe_scope` that assessment already made. The one
//! write is local: [`assign_ids`] records each new rotation at step
//! `planned` in the state file so apply can require a matching id.
//!
//! Nothing here prints. [`render_table`] and [`render_json`] return strings
//! for the binary to print. A [`PlannedRotation`] holds the credential for
//! apply, so it has no `Serialize`; JSON goes through views that carry
//! fingerprints, consumer references and reasons only.

use std::fmt::Write as _;

use serde::Serialize;

use crate::assess::{Assessed, Disposition};
use crate::config::{ConsumersConfig, Overlap, ProviderName};
use crate::consumer::{ConsumerMatch, ConsumerRegistry, Holds, MatchMethod, SecretRef};
use crate::finding::SourceLocation;
use crate::provider::{Credential, ProviderRegistry, ReplacementMode, Scope, Validity};
use crate::secret::Fingerprint;
use crate::state::{ConsumerState, ConsumerStatus, Step};
#[cfg(unix)]
use crate::state::{Rotation, StateError, StateStore};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Version of the `--json` document; bumped on any incompatible change to
/// `docs/plan-schema.json`.
pub const PLAN_JSON_VERSION: u32 = 1;

/// Replacement wording for a provider in manual mode (decision D1).
pub const MANUAL_REPLACEMENT: &str = "manual: you will be asked to paste the new secret";

/// How the replacement row continues in manual mode when the provider's
/// automatic replacement would widen scope (SHA-291).
pub const MANUAL_NOT_WIDER: &str = "automatic replacement is off because";

/// Skip reason for a secret whose rotation already finished (SHA-258).
pub const ALREADY_ROTATED: &str = "already rotated";

/// Skip reason for a secret that no longer works and whose rotation in the
/// state file waits at `revoke_manual` (SHA-289): the operator deleted it by
/// hand. Apply records that rotation `revoked`.
pub const REVOKED_BY_HAND: &str = "revoked by hand";

/// Blocker for a credential the provider cannot revoke (see
/// [`Provider::manual_revoke`](crate::provider::Provider::manual_revoke)).
pub const MANUAL_REVOKE_BLOCKER: &str =
    "rotate cannot revoke this credential; apply updates consumers and verifies, then stops at revoke: delete the old one by hand";

/// The provider and consumer matrix (SHA-266), named in the plan when a
/// step is manual or unsupported.
pub const PROVIDER_MATRIX_DOC: &str = "docs/providers.md";

/// Closing line of the plan when any rotation has a manual or unsupported
/// step.
pub const PROVIDER_MATRIX_NOTE: &str = "Some steps above are manual or cannot be automated. \
     See docs/providers.md (https://github.com/smhasan94/rotate/blob/main/docs/providers.md) \
     for what rotate does per provider and consumer, and what to do by hand.";

/// Blocker wording shared by every reason apply would stop before revoke.
const REFUSE_REVOKE: &str = "apply will refuse to revoke without --force";

/// Everything `rotate plan` found, in the order secrets were first seen.
#[derive(Debug, Clone)]
pub struct Plan {
    /// Time between the consumer update and the revoke (decision D2).
    pub overlap_window: Overlap,
    /// Secrets that will be rotated.
    pub rotations: Vec<PlannedRotation>,
    /// Secrets that will not, with the reason.
    pub skipped: Vec<Skipped>,
}

/// One secret that apply would rotate.
#[derive(Debug, Clone)]
pub struct PlannedRotation {
    /// Id apply requires (`--confirm`). Empty until [`assign_ids`] runs.
    pub rotation_id: String,
    /// Owning provider.
    pub provider: &'static str,
    /// Fingerprint of the secret half.
    pub fingerprint: Fingerprint,
    /// The credential to rotate. Never serialized.
    pub credential: Credential,
    /// Owner and reach, when `describe_scope` succeeded.
    pub scope: Option<Scope>,
    /// Why `describe_scope` failed, when it did.
    pub scope_error: Option<String>,
    /// Whether the provider mints the replacement or the operator pastes it.
    pub replacement_mode: ReplacementMode,
    /// Why the provider's automatic replacement would be broader than the
    /// leaked credential (SHA-291); see
    /// [`Provider::scope_widening`](crate::provider::Provider::scope_widening).
    pub scope_widening: Option<&'static str>,
    /// Every place the secret is used.
    pub consumers: Vec<PlannedConsumer>,
    /// Consumers whose lookup failed.
    pub lookup_errors: Vec<LookupError>,
    /// What revoke does at this provider.
    pub revoke_action: &'static str,
    /// Copy of [`Plan::overlap_window`], so a rotation reads on its own.
    pub overlap_window: Overlap,
    /// Why the provider's revoke would fail as configured now (see
    /// [`Provider::revoke_blocker`](crate::provider::Provider::revoke_blocker)),
    /// for example no npm operator token (SHA-292). Also in `blockers`.
    pub revoke_blocker: Option<String>,
    /// Why apply would stop before the revoke. Empty when nothing blocks.
    pub blockers: Vec<String>,
    /// Step recorded in the state file; `planned` for a new rotation.
    pub step: Step,
    /// Every location that held the secret.
    pub sources: Vec<SourceLocation>,
    /// What an earlier run recorded for this rotation (SHA-294), set by
    /// [`assign_ids`] when it keeps a stored id. `None` for a new rotation.
    pub recorded: Option<Recorded>,
}

/// The part of a stored rotation the plan shows on a re-run (SHA-294):
/// the consumers an earlier run touched, which the plan's own `find` may
/// no longer match (a consumer matched by value now holds the
/// replacement), and the revoke time it recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recorded {
    /// Every consumer the rotation recorded, with its recorded status.
    pub consumers: Vec<ConsumerState>,
    /// Earliest revoke time, as recorded.
    pub revoke_not_before: Option<OffsetDateTime>,
}

/// One consumer match, with the plugin that found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedConsumer {
    /// Consumer plugin name, for example `github-actions`.
    pub consumer: &'static str,
    /// What `find` returned.
    pub found: ConsumerMatch,
}

/// A consumer whose `find` failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupError {
    /// Consumer plugin name.
    pub consumer: &'static str,
    /// The error text. Consumers keep it value-free (SHA-222).
    pub error: String,
}

/// A secret that will not be rotated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// Fingerprint of the secret half.
    pub fingerprint: Fingerprint,
    /// Owning provider, when one was identified.
    pub provider: Option<&'static str>,
    /// One of `invalid`, `unsupported`, `not rotatable`, `unknown`,
    /// `unchecked`, `already rotated`, `revoked by hand`.
    pub reason: &'static str,
    /// More detail, for example why validity is unknown.
    pub detail: Option<String>,
    /// Every location that held the secret.
    pub sources: Vec<SourceLocation>,
    /// The rotation in the state file this secret belongs to, for reason
    /// `revoked by hand` (SHA-289). Not part of the plan JSON.
    pub rotation_id: Option<String>,
}

/// Actions secret names for a provider (decision D4), split by which half
/// of the credential each holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConsumerNames {
    /// Names that hold the secret or token.
    pub secret: Vec<String>,
    /// Names that hold an access key id.
    pub key_id: Vec<String>,
}

impl ConsumerNames {
    /// Every name, secret names first.
    pub fn all(&self) -> impl Iterator<Item = &String> {
        self.secret.iter().chain(&self.key_id)
    }
}

fn provider_name(provider: &str) -> Option<ProviderName> {
    match provider {
        "aws" => Some(ProviderName::Aws),
        "github" => Some(ProviderName::Github),
        "npm" => Some(ProviderName::Npm),
        "openai" => Some(ProviderName::Openai),
        _ => None,
    }
}

/// The D4 name convention for `provider` plus the `rotate.yaml` mappings
/// (`consumers.github_actions.secret_names` and `key_id_names`), deduped in
/// order. Consumers that cannot read values back match by these names.
pub fn consumer_names(provider: &str, config: &ConsumersConfig) -> ConsumerNames {
    let (secret, key_id): (&[&str], &[&str]) = match provider_name(provider) {
        Some(ProviderName::Aws) => (&["AWS_SECRET_ACCESS_KEY"], &["AWS_ACCESS_KEY_ID"]),
        // No GITHUB_TOKEN: GitHub rejects Actions secret names starting with
        // GITHUB_, so it could never match.
        Some(ProviderName::Github) => (&["GH_TOKEN", "GH_PAT"], &[]),
        Some(ProviderName::Npm) => (&["NPM_TOKEN"], &[]),
        Some(ProviderName::Openai) => (&["OPENAI_API_KEY"], &[]),
        None => (&[], &[]),
    };
    let merge = |convention: &[&str], extra: Option<&Vec<String>>| {
        let mut names: Vec<String> = Vec::new();
        for name in convention
            .iter()
            .map(|n| (*n).to_owned())
            .chain(extra.into_iter().flatten().cloned())
        {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        names
    };
    let actions = &config.github_actions;
    let key = provider_name(provider);
    ConsumerNames {
        secret: merge(secret, key.and_then(|k| actions.secret_names.get(&k))),
        key_id: merge(key_id, key.and_then(|k| actions.key_id_names.get(&k))),
    }
}

/// What revoke does at `provider`, as shown in the plan.
pub fn revoke_action(provider: &str) -> &'static str {
    match provider {
        "aws" => "deactivate the access key (not deleted; rollback can reactivate it)",
        "github" => "revoke the token (GitHub credential revocation API)",
        "npm" => "delete the access token",
        "openai" => "delete the API key (OpenAI Admin API)",
        _ => "revoke the credential",
    }
}

impl PlannedRotation {
    /// The replacement step as shown in the plan. In manual mode it says
    /// why when an automatic replacement would widen scope (SHA-291).
    pub fn replacement_text(&self) -> String {
        match self.replacement_mode {
            ReplacementMode::Manual => match self.scope_widening {
                Some(why) => format!(
                    "{MANUAL_REPLACEMENT} ({MANUAL_NOT_WIDER} {why}; {})",
                    opt_in_hint(self.provider)
                ),
                None => MANUAL_REPLACEMENT.to_owned(),
            },
            ReplacementMode::Automatic => match &self.scope {
                Some(scope) => format!(
                    "create a new {} credential for {}",
                    self.provider, scope.identity
                ),
                None => format!("create a new {} credential", self.provider),
            },
        }
    }

    /// The scope-widening note when the replacement rotate creates is
    /// broader than the leaked credential: automatic mode only.
    pub fn widens_scope(&self) -> Option<&'static str> {
        match self.replacement_mode {
            ReplacementMode::Automatic => self.scope_widening,
            ReplacementMode::Manual => None,
        }
    }

    /// The status an earlier run recorded for `consumer_ref` (SHA-294).
    pub fn recorded_status(&self, consumer_ref: &str) -> Option<ConsumerStatus> {
        self.recorded
            .as_ref()?
            .consumers
            .iter()
            .find(|c| c.consumer_ref == consumer_ref)
            .map(|c| c.status)
    }

    /// Consumers an earlier run recorded that this plan's `find` did not
    /// match (SHA-294), for example a Secrets Manager entry matched by value
    /// that now holds the replacement.
    pub fn recorded_only(&self) -> impl Iterator<Item = &ConsumerState> {
        self.recorded.iter().flat_map(|r| &r.consumers).filter(|c| {
            !self
                .consumers
                .iter()
                .any(|p| p.found.consumer_ref == c.consumer_ref)
        })
    }

    /// The revoke time an earlier run recorded, while the rotation waits
    /// for it at `pending_revoke` (SHA-294). Apply keeps that time rather
    /// than the overlap window of this run.
    pub fn recorded_revoke_time(&self) -> Option<OffsetDateTime> {
        if self.step != Step::PendingRevoke {
            return None;
        }
        self.recorded.as_ref()?.revoke_not_before
    }

    /// The `overlap:` row at `now`: the window of this run, or for a
    /// pending revoke the recorded time and what is left of it (SHA-294).
    pub fn overlap_text(&self, now: OffsetDateTime) -> String {
        match self.recorded_revoke_time() {
            Some(at) if at > now => format!(
                "revoke after {} (in {}; recorded by an earlier run)",
                rfc3339(at),
                crate::apply::remaining_text(at - now)
            ),
            Some(at) => format!(
                "window over at {} (recorded by an earlier run); apply revokes now",
                rfc3339(at)
            ),
            None => self.overlap_window.to_string(),
        }
    }

    /// Matches that cannot be updated automatically.
    pub fn not_updatable(&self) -> impl Iterator<Item = &PlannedConsumer> {
        self.consumers.iter().filter(|c| !c.found.is_updatable())
    }

    /// True when a step needs the operator: a pasted replacement, a revoke
    /// rotate cannot do, or a consumer it cannot update (SHA-266).
    pub fn has_manual_step(&self) -> bool {
        self.replacement_mode == ReplacementMode::Manual
            || self.blockers.iter().any(|b| b == MANUAL_REVOKE_BLOCKER)
            || self.not_updatable().next().is_some()
    }
}

/// How to opt in to a broader automatic replacement for `provider`.
fn opt_in_hint(provider: &str) -> String {
    match provider_name(provider) {
        Some(ProviderName::Openai) => crate::provider::openai::OPT_IN_HINT.to_owned(),
        _ => "opt in with --allow-broader-replacement".to_owned(),
    }
}

fn skipped(item: Assessed, reason: &'static str, detail: Option<String>) -> Skipped {
    let provider = match item.disposition {
        Disposition::Supported { provider, .. } => Some(provider),
        _ => None,
    };
    Skipped {
        fingerprint: item.fingerprint,
        provider,
        reason,
        detail,
        sources: item.sources,
        rotation_id: None,
    }
}

/// Builds the plan from `assessed`. Valid secrets become rotations and every
/// registered consumer is asked for them with `find`; everything else is
/// skipped without a consumer call. Never fails: a consumer error becomes a
/// [`LookupError`] and a blocker.
pub async fn build(
    assessed: Vec<Assessed>,
    providers: &ProviderRegistry,
    consumers: &ConsumerRegistry,
    overlap_window: Overlap,
    consumers_config: &ConsumersConfig,
) -> Plan {
    let mut plan = Plan {
        overlap_window,
        rotations: Vec::new(),
        skipped: Vec::new(),
    };
    for item in assessed {
        let provider = match &item.disposition {
            Disposition::Unsupported { reason } => {
                let reason = reason.clone();
                plan.skipped.push(skipped(item, "unsupported", reason));
                continue;
            }
            Disposition::NotRotatable { reason } => {
                let reason = reason.clone();
                plan.skipped
                    .push(skipped(item, "not rotatable", Some(reason)));
                continue;
            }
            Disposition::Supported { provider, .. } => *provider,
        };
        match &item.validity {
            Some(Validity::Valid) => {}
            Some(Validity::Invalid) => {
                plan.skipped.push(skipped(item, "invalid", None));
                continue;
            }
            Some(Validity::Unknown { reason }) => {
                let reason = reason.clone();
                plan.skipped.push(skipped(item, "unknown", Some(reason)));
                continue;
            }
            None => {
                plan.skipped.push(skipped(item, "unchecked", None));
                continue;
            }
        }

        let names = consumer_names(provider, consumers_config);
        let secret = SecretRef::new(provider, &item.credential).with_names(names.all().cloned());
        let mut planned = Vec::new();
        let mut lookup_errors = Vec::new();
        for found in consumers.find_all(&secret).await {
            match found.result {
                Ok(matches) => planned.extend(matches.into_iter().map(|m| PlannedConsumer {
                    consumer: found.consumer,
                    found: m,
                })),
                Err(err) => lookup_errors.push(LookupError {
                    consumer: found.consumer,
                    error: err.to_string(),
                }),
            }
        }

        let manual_revoke = providers
            .get(provider)
            .and_then(|p| p.manual_revoke(item.scope.as_ref()));
        // A revoke done by hand needs no operator credential.
        let revoke_blocker = match manual_revoke {
            Some(_) => None,
            None => providers
                .get(provider)
                .and_then(|p| p.revoke_blocker(&item.credential, item.scope.as_ref())),
        };
        let mut rotation = PlannedRotation {
            rotation_id: String::new(),
            provider,
            fingerprint: item.fingerprint,
            credential: item.credential,
            scope: item.scope,
            scope_error: item.scope_error,
            replacement_mode: providers
                .get(provider)
                .map_or(ReplacementMode::Automatic, |p| p.replacement_mode()),
            scope_widening: providers.get(provider).and_then(|p| p.scope_widening()),
            consumers: planned,
            lookup_errors,
            revoke_action: manual_revoke.unwrap_or_else(|| revoke_action(provider)),
            overlap_window,
            revoke_blocker,
            blockers: Vec::new(),
            step: Step::Planned,
            sources: item.sources,
            recorded: None,
        };
        rotation.blockers = blockers(&rotation);
        if manual_revoke.is_some() {
            rotation.blockers.push(MANUAL_REVOKE_BLOCKER.to_owned());
        }
        plan.rotations.push(rotation);
    }
    plan
}

pub(crate) fn blockers(rotation: &PlannedRotation) -> Vec<String> {
    let mut blockers = Vec::new();
    let stuck = rotation.not_updatable().count();
    if stuck > 0 {
        let noun = if stuck == 1 {
            "consumer cannot"
        } else {
            "consumers cannot"
        };
        blockers.push(format!("{stuck} {noun} be updated; {REFUSE_REVOKE}"));
    }
    for err in &rotation.lookup_errors {
        blockers.push(format!(
            "consumer {} could not be searched; {REFUSE_REVOKE}",
            err.consumer
        ));
    }
    blockers.extend(rotation.revoke_blocker.clone());
    blockers
}

/// Gives every rotation its id and records new ones at step `planned`.
///
/// An unfinished rotation in the state file for the same provider and
/// fingerprint keeps its id, so running `plan` twice gives the same ids. So
/// does a finished one whose rollback is in progress (SHA-258): apply then
/// reports the rollback instead of starting a second rotation.
/// Its stored step is copied onto the plan and the record is not touched,
/// so `plan` never rewinds an `apply` in progress. Anything else gets a new
/// id. Writes the state file only; no remote call.
#[cfg(unix)]
pub fn assign_ids(plan: &mut Plan, store: &mut StateStore) -> Result<(), StateError> {
    for rotation in &mut plan.rotations {
        let existing = store
            .rotations()
            .iter()
            .filter(|r| {
                (r.is_in_progress() || r.is_rolling_back())
                    && r.provider == rotation.provider
                    && r.fingerprint == rotation.fingerprint
            })
            .max_by_key(|r| r.updated_at)
            .cloned();
        if let Some(record) = existing {
            adopt(rotation, record);
            continue;
        }
        let id = mint_id(&rotation.fingerprint, |id| store.get(id).is_some());
        store.upsert(Rotation::new(
            id.clone(),
            rotation.provider,
            rotation.fingerprint.clone(),
        ))?;
        rotation.rotation_id = id;
        rotation.step = Step::Planned;
    }
    Ok(())
}

/// Carries the stored `record` onto the plan's `rotation` (SHA-294): its
/// id, step, consumers and revoke time. Once the record has a replacement,
/// a provider warning that names it (AWS: both key slots used, one of them
/// by this rotation's own replacement) is about a create that will not
/// happen again, so it becomes a plain scope line.
#[cfg(unix)]
fn adopt(rotation: &mut PlannedRotation, record: Rotation) {
    if let (Some(replacement), Some(scope)) = (&record.replacement_ref, &mut rotation.scope) {
        if !replacement.is_empty() {
            let mut own = false;
            scope.lines.retain(|line| {
                let names_it = line.starts_with("warning: ") && line.contains(replacement.as_str());
                own |= names_it;
                !names_it
            });
            if own {
                scope.lines.push(format!(
                    "replacement: {replacement}, created by rotation {}",
                    record.rotation_id
                ));
            }
        }
    }
    rotation.rotation_id = record.rotation_id;
    rotation.step = record.step;
    rotation.recorded = Some(Recorded {
        consumers: record.consumers,
        revoke_not_before: record.revoke_not_before,
    });
}

/// A fresh `rot-` id with 8 hex characters, not yet in use.
#[cfg(unix)]
fn mint_id(fingerprint: &Fingerprint, taken: impl Fn(&str) -> bool) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use sha2::{Digest, Sha256};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    loop {
        let mut hasher = Sha256::new();
        hasher.update(fingerprint.as_str().as_bytes());
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        hasher.update(nanos.to_le_bytes());
        hasher.update(std::process::id().to_le_bytes());
        hasher.update(COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes());
        let digest = hasher.finalize();
        let mut id = String::from("rot-");
        for byte in &digest[..4] {
            // Writing to a String cannot fail.
            let _ = write!(id, "{byte:02x}");
        }
        if !taken(&id) {
            return id;
        }
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
        Step::RevokeManual => "revoke_manual",
        Step::RolledBack => "rolled_back",
    }
}

/// What `rotate apply` will do with a rotation an earlier run left at
/// `step` (SHA-258). A rollback in progress is reported by apply itself.
fn resume_text(step: Step) -> &'static str {
    match step {
        Step::Planned => "rotate apply runs it",
        Step::Created => {
            "the replacement value from the earlier run is gone, so rotate apply will mark it needs_rollback"
        }
        Step::ConsumersUpdated => "rotate apply resumes it at verify",
        Step::Verified => "rotate apply resumes it at revoke",
        Step::PendingRevoke => "rotate apply revokes once the overlap window has passed",
        Step::Failed => "rotate apply resumes it where it can",
        Step::NeedsRollback => "run rotate rollback with the same input",
        Step::RevokeManual => {
            "the old secret must be deleted by hand; rotate apply records it revoked once it no longer works"
        }
        Step::Revoked | Step::RolledBack => "a rollback of it is in progress",
    }
}

/// Marks every secret skipped as `invalid` whose latest rotation in
/// `rotations` (same provider and fingerprint) waits at `revoke_manual`,
/// with no rollback of it in progress (SHA-289): its reason becomes
/// [`REVOKED_BY_HAND`] and its detail names the rotation. Assessment's
/// read-only `check_valid` found the old secret no longer works, so the
/// operator deleted it as asked. Local and pure: `apply` records the
/// rotation `revoked`; `plan` only shows the row.
#[cfg(unix)]
pub fn mark_revoked_by_hand(plan: &mut Plan, rotations: &[Rotation]) {
    for skipped in plan.skipped.iter_mut().filter(|s| s.reason == "invalid") {
        let Some(provider) = skipped.provider else {
            continue;
        };
        let latest = rotations
            .iter()
            .filter(|r| r.provider == provider && r.fingerprint == skipped.fingerprint)
            .max_by_key(|r| r.updated_at);
        if let Some(waiting) =
            latest.filter(|r| r.step == Step::RevokeManual && !r.is_rolling_back())
        {
            skipped.reason = REVOKED_BY_HAND;
            skipped.rotation_id = Some(waiting.rotation_id.clone());
            skipped.detail = Some(format!(
                "rotation {} waited for the old secret to be deleted by hand; it no longer works, so rotate apply records it revoked",
                waiting.rotation_id
            ));
        }
    }
}

/// Splits off the findings whose secret was already rotated: the latest
/// rotation in `rotations` for its fingerprint is `revoked` and no rollback
/// of it is in progress (SHA-258, FR22). They are returned as skipped with
/// reason `already rotated`, before identification, so `plan` and `apply`
/// make no provider or consumer call for them. Local and pure.
#[cfg(unix)]
pub fn split_already_rotated(
    findings: Vec<crate::finding::Finding>,
    rotations: &[Rotation],
    providers: &ProviderRegistry,
) -> (Vec<crate::finding::Finding>, Vec<Skipped>) {
    let mut kept = Vec::new();
    let mut skipped: Vec<Skipped> = Vec::new();
    for finding in findings {
        let fingerprint = finding.fingerprint();
        let latest = rotations
            .iter()
            .filter(|r| r.fingerprint == fingerprint)
            .max_by_key(|r| r.updated_at);
        let Some(done) = latest.filter(|r| r.step == Step::Revoked && !r.is_rolling_back()) else {
            kept.push(finding);
            continue;
        };
        if let Some(entry) = skipped.iter_mut().find(|s| s.fingerprint == fingerprint) {
            entry.sources.push(finding.source.clone());
            continue;
        }
        let when = done
            .updated_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| done.updated_at.to_string());
        skipped.push(Skipped {
            fingerprint,
            provider: providers.get(&done.provider).map(|p| p.name()),
            reason: ALREADY_ROTATED,
            detail: Some(format!(
                "rotation {} already rotated on {when}; nothing to do",
                done.rotation_id
            )),
            sources: vec![finding.source.clone()],
            rotation_id: None,
        });
    }
    (kept, skipped)
}

fn rfc3339(at: OffsetDateTime) -> String {
    at.format(&Rfc3339).unwrap_or_else(|_| at.to_string())
}

/// The snake_case name of a recorded consumer status.
fn status_name(status: ConsumerStatus) -> &'static str {
    match status {
        ConsumerStatus::Updated => "updated",
        ConsumerStatus::Failed => "failed",
        ConsumerStatus::Skipped => "skipped",
        ConsumerStatus::Restored => "restored",
    }
}

fn match_name(method: MatchMethod) -> &'static str {
    match method {
        MatchMethod::ByValue => "by value",
        MatchMethod::ByName => "by name",
    }
}

fn holds_name(holds: Holds) -> &'static str {
    match holds {
        Holds::Secret => "secret",
        Holds::KeyId => "key_id",
        Holds::KeyPair => "key_pair",
    }
}

fn sources_text(sources: &[SourceLocation]) -> String {
    match sources.split_first() {
        Some((first, [])) => first.to_string(),
        Some((first, rest)) => format!("{first} (+{} more)", rest.len()),
        None => "-".to_owned(),
    }
}

/// Left-aligned columns two spaces apart, trailing space trimmed.
fn columns(rows: &[Vec<String>], indent: &str) -> String {
    let count = rows.iter().map(Vec::len).max().unwrap_or(0);
    let mut widths = vec![0; count];
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.len());
        }
    }
    let mut out = String::new();
    for row in rows {
        let mut line = String::from(indent);
        for (cell, width) in row.iter().zip(&widths) {
            let _ = write!(line, "{cell:<width$}  ");
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// One `label: value` line of a rotation block.
fn field(out: &mut String, label: &str, value: &str) {
    let _ = writeln!(out, "  {label:<14}{value}");
}

/// Human-readable plan: one block per rotation, then the skipped secrets.
pub fn render_table(plan: &Plan) -> String {
    render_with_header(plan, "Plan", "Dry run: nothing was changed.")
}

/// [`render_table`] as `rotate apply` prints it before asking for
/// confirmation: the header says what is about to happen instead of
/// calling it a dry run (SHA-256).
pub fn render_apply_table(plan: &Plan) -> String {
    render_with_header(plan, "Plan to apply", "Nothing has been changed yet.")
}

fn render_with_header(plan: &Plan, title: &str, note: &str) -> String {
    render_at(plan, title, note, OffsetDateTime::now_utc())
}

fn render_at(plan: &Plan, title: &str, note: &str, now: OffsetDateTime) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{title}: {} to rotate, {} skipped. {note}",
        plan.rotations.len(),
        plan.skipped.len()
    );
    for r in &plan.rotations {
        out.push('\n');
        let _ = writeln!(
            out,
            "Rotation {}  {}  {}",
            r.rotation_id, r.provider, r.fingerprint
        );
        let identity = r
            .scope
            .as_ref()
            .map_or_else(|| "-".to_owned(), |s| s.identity.to_string());
        field(&mut out, "identity:", &identity);
        field(&mut out, "sources:", &sources_text(&r.sources));
        if let Some(err) = &r.scope_error {
            field(&mut out, "scope:", &format!("unavailable: {err}"));
        }
        // Scope lines a provider marks as warnings (AWS: both key slots used).
        for warning in r.scope.iter().flat_map(|s| &s.lines) {
            if let Some(text) = warning.strip_prefix("warning: ") {
                field(&mut out, "warning:", text);
            }
        }
        if r.step != Step::Planned {
            let state = format!(
                "in progress at step {}; {}",
                step_name(r.step),
                resume_text(r.step)
            );
            field(&mut out, "state:", &state);
        }
        field(&mut out, "replacement:", &r.replacement_text());
        if let Some(note) = r.widens_scope() {
            let _ = writeln!(out, "  scope widening: {note}");
        }
        if r.consumers.is_empty()
            && r.lookup_errors.is_empty()
            && r.recorded_only().next().is_none()
        {
            field(&mut out, "consumers:", "none found");
        } else {
            out.push_str("  consumers:\n");
            let mut rows: Vec<Vec<String>> = r
                .consumers
                .iter()
                .map(|c| {
                    let planned = match &c.found.updatable {
                        Ok(()) => "update".to_owned(),
                        Err(blocked) => format!("cannot update: {blocked}"),
                    };
                    // SHA-294: on a re-run, what the earlier run recorded.
                    let action = match r.recorded_status(&c.found.consumer_ref) {
                        Some(ConsumerStatus::Updated) => "updated (recorded)".to_owned(),
                        Some(status) => format!("{planned} (recorded: {})", status_name(status)),
                        None => planned,
                    };
                    vec![
                        c.consumer.to_owned(),
                        c.found.consumer_ref.clone(),
                        match_name(c.found.match_method).to_owned(),
                        action,
                    ]
                })
                .collect();
            rows.extend(r.recorded_only().map(|c| {
                vec![
                    c.consumer.clone(),
                    c.consumer_ref.clone(),
                    "recorded".to_owned(),
                    format!("{} (recorded)", status_name(c.status)),
                ]
            }));
            rows.extend(r.lookup_errors.iter().map(|e| {
                vec![
                    e.consumer.to_owned(),
                    "-".to_owned(),
                    "-".to_owned(),
                    format!("lookup failed: {}", e.error),
                ]
            }));
            out.push_str(&columns(&rows, "    "));
        }
        field(&mut out, "revoke:", r.revoke_action);
        field(&mut out, "overlap:", &r.overlap_text(now));
        if !r.blockers.is_empty() {
            out.push_str("  blockers:\n");
            for blocker in &r.blockers {
                let _ = writeln!(out, "    - {blocker}");
            }
        }
    }
    if !plan.skipped.is_empty() {
        out.push_str("\nSkipped:\n");
        let mut rows = vec![vec![
            "PROVIDER".to_owned(),
            "FINGERPRINT".to_owned(),
            "REASON".to_owned(),
            "SOURCE".to_owned(),
        ]];
        let mut notes = Vec::new();
        for s in &plan.skipped {
            if let Some(detail) = &s.detail {
                notes.push(format!("  {}  {}: {detail}", s.fingerprint, s.reason));
            }
            rows.push(vec![
                s.provider.unwrap_or("-").to_owned(),
                s.fingerprint.to_string(),
                s.reason.to_owned(),
                sources_text(&s.sources),
            ]);
        }
        out.push_str(&columns(&rows, ""));
        if !notes.is_empty() {
            out.push_str("\nNotes:\n");
            for note in notes {
                out.push_str(&note);
                out.push('\n');
            }
        }
    }
    if plan.rotations.iter().any(PlannedRotation::has_manual_step) {
        out.push('\n');
        out.push_str(PROVIDER_MATRIX_NOTE);
        out.push('\n');
    }
    out
}

#[derive(Serialize)]
struct PlanView<'a> {
    version: u32,
    overlap_window: String,
    rotations: Vec<RotationView<'a>>,
    skipped: Vec<SkippedView<'a>>,
}

#[derive(Serialize)]
struct RotationView<'a> {
    rotation_id: &'a str,
    provider: &'static str,
    fingerprint: &'a Fingerprint,
    validity: &'static str,
    state: &'static str,
    scope: Option<ScopeView<'a>>,
    scope_error: Option<&'a str>,
    replacement: ReplacementView,
    consumers: Vec<ConsumerView<'a>>,
    lookup_errors: Vec<LookupErrorView<'a>>,
    revoke_action: &'static str,
    overlap_window: String,
    blockers: &'a [String],
    sources: Vec<String>,
    recorded: Option<RecordedView<'a>>,
}

/// What an earlier run recorded (SHA-294); null for a new rotation.
#[derive(Serialize)]
struct RecordedView<'a> {
    #[serde(with = "time::serde::rfc3339::option")]
    revoke_not_before: Option<OffsetDateTime>,
    consumers: Vec<RecordedConsumerView<'a>>,
}

#[derive(Serialize)]
struct RecordedConsumerView<'a> {
    consumer: &'a str,
    consumer_ref: &'a str,
    status: &'static str,
}

#[derive(Serialize)]
struct ScopeView<'a> {
    identity: &'a str,
    lines: &'a [String],
}

#[derive(Serialize)]
struct ReplacementView {
    mode: &'static str,
    action: String,
    scope_widening: Option<&'static str>,
}

#[derive(Serialize)]
struct ConsumerView<'a> {
    consumer: &'static str,
    consumer_ref: &'a str,
    match_method: &'static str,
    holds: &'static str,
    updatable: bool,
    reason: Option<&'a str>,
}

#[derive(Serialize)]
struct LookupErrorView<'a> {
    consumer: &'static str,
    error: &'a str,
}

#[derive(Serialize)]
struct SkippedView<'a> {
    provider: Option<&'static str>,
    fingerprint: &'a Fingerprint,
    reason: &'static str,
    detail: Option<&'a str>,
    sources: Vec<String>,
}

/// The plan as pretty-printed JSON, described by `docs/plan-schema.json`.
/// Field names are part of the CLI contract.
pub fn render_json(plan: &Plan) -> String {
    let view = PlanView {
        version: PLAN_JSON_VERSION,
        overlap_window: plan.overlap_window.to_string(),
        rotations: plan
            .rotations
            .iter()
            .map(|r| RotationView {
                rotation_id: &r.rotation_id,
                provider: r.provider,
                fingerprint: &r.fingerprint,
                validity: "valid",
                state: step_name(r.step),
                scope: r.scope.as_ref().map(|s| ScopeView {
                    identity: &s.identity.0,
                    lines: &s.lines,
                }),
                scope_error: r.scope_error.as_deref(),
                replacement: ReplacementView {
                    mode: match r.replacement_mode {
                        ReplacementMode::Automatic => "automatic",
                        ReplacementMode::Manual => "manual",
                    },
                    action: r.replacement_text(),
                    scope_widening: r.widens_scope(),
                },
                consumers: r
                    .consumers
                    .iter()
                    .map(|c| ConsumerView {
                        consumer: c.consumer,
                        consumer_ref: &c.found.consumer_ref,
                        match_method: match c.found.match_method {
                            MatchMethod::ByValue => "by_value",
                            MatchMethod::ByName => "by_name",
                        },
                        holds: holds_name(c.found.holds),
                        updatable: c.found.is_updatable(),
                        reason: c.found.updatable.as_ref().err().map(|e| e.reason.as_str()),
                    })
                    .collect(),
                lookup_errors: r
                    .lookup_errors
                    .iter()
                    .map(|e| LookupErrorView {
                        consumer: e.consumer,
                        error: &e.error,
                    })
                    .collect(),
                revoke_action: r.revoke_action,
                overlap_window: r.overlap_window.to_string(),
                blockers: &r.blockers,
                sources: r.sources.iter().map(ToString::to_string).collect(),
                recorded: r.recorded.as_ref().map(|rec| RecordedView {
                    revoke_not_before: rec.revoke_not_before,
                    consumers: rec
                        .consumers
                        .iter()
                        .map(|c| RecordedConsumerView {
                            consumer: &c.consumer,
                            consumer_ref: &c.consumer_ref,
                            status: status_name(c.status),
                        })
                        .collect(),
                }),
            })
            .collect(),
        skipped: plan
            .skipped
            .iter()
            .map(|s| SkippedView {
                provider: s.provider,
                fingerprint: &s.fingerprint,
                reason: s.reason,
                detail: s.detail.as_deref(),
                sources: s.sources.iter().map(ToString::to_string).collect(),
            })
            .collect(),
    };
    serde_json::to_string_pretty(&view).expect("the view holds only strings, lists and numbers")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use super::*;
    use crate::assess::{assess, AssessOptions};
    use crate::calls::CallLog;
    use crate::consumer::mock::MockConsumer;
    use crate::consumer::ConsumerError;
    use crate::finding::Finding;
    use crate::provider::mock::MockProvider;
    use crate::secret::SecretValue;

    fn finding(value: &str) -> Finding {
        Finding::new(
            SecretValue::from(value),
            "Mock",
            SourceLocation::file("a.env"),
        )
    }

    fn fp(value: &str) -> Fingerprint {
        SecretValue::from(value).fingerprint()
    }

    async fn plan_for(
        values: &[&str],
        provider: MockProvider,
        consumers: Vec<MockConsumer>,
        log: &CallLog,
    ) -> Plan {
        let mut providers = ProviderRegistry::new();
        providers.register(Arc::new(provider.log(log.clone())));
        let mut registry = ConsumerRegistry::new();
        for consumer in consumers {
            registry.register(Arc::new(consumer.log(log.clone())));
        }
        let assessed = assess(
            values.iter().map(|v| finding(v)).collect(),
            &providers,
            &AssessOptions::default(),
        )
        .await;
        build(
            assessed,
            &providers,
            &registry,
            "1h".parse().unwrap(),
            &ConsumersConfig::default(),
        )
        .await
    }

    // T1 (AC1), T2 (AC2)
    #[tokio::test]
    async fn build_valid_secret_with_two_matches() {
        let log = CallLog::new();
        let value = "npm_plan_unit_two_matches";
        let gha = MockConsumer::new("github-actions")
            .matching(fp(value), ConsumerMatch::by_name("gha:org/repo:NPM_TOKEN"));
        let sm = MockConsumer::new("aws-secrets-manager")
            .matching(fp(value), ConsumerMatch::by_value("sm:prod/npm"));
        let provider = MockProvider::new("npm").identify_prefix("npm_");
        let plan = plan_for(&[value], provider, vec![gha, sm], &log).await;

        assert_eq!(plan.rotations.len(), 1);
        let r = &plan.rotations[0];
        assert_eq!(r.consumers.len(), 2);
        assert_eq!(r.consumers[0].consumer, "github-actions");
        assert_eq!(r.revoke_action, "delete the access token");
        assert_eq!(r.overlap_window.to_string(), "1h");
        assert!(r.blockers.is_empty());
        assert_eq!(
            r.replacement_text(),
            "create a new npm credential for npm-user"
        );
        let table = render_table(&plan);
        assert!(table.contains("gha:org/repo:NPM_TOKEN"), "{table}");
        assert!(table.contains("sm:prod/npm"), "{table}");
        assert!(table.contains("  overlap:      1h\n"), "{table}");
        // SHA-266: nothing manual, so no pointer to the matrix.
        assert!(!table.contains(PROVIDER_MATRIX_DOC), "{table}");
        log.assert_no_mutations();
    }

    // T3 (AC3), T7 (AC7)
    #[tokio::test]
    async fn not_updatable_blocks_and_manual_wording() {
        let log = CallLog::new();
        let value = "npm_plan_unit_blocked";
        let gha = MockConsumer::new("github-actions").matching(
            fp(value),
            ConsumerMatch::by_name("gha:org:NPM_TOKEN").not_updatable("org secret needs admin"),
        );
        let provider = MockProvider::new("npm")
            .identify_prefix("npm_")
            .mode(ReplacementMode::Manual);
        let plan = plan_for(&[value], provider, vec![gha], &log).await;
        let r = &plan.rotations[0];
        assert_eq!(
            r.blockers,
            ["1 consumer cannot be updated; apply will refuse to revoke without --force"]
        );
        assert_eq!(r.replacement_text(), MANUAL_REPLACEMENT);
        assert!(r.has_manual_step());
        // SHA-266 T3 (AC3): the plan names the provider matrix.
        let table = render_table(&plan);
        assert!(
            table.ends_with(&format!("\n{PROVIDER_MATRIX_NOTE}\n")),
            "{table}"
        );
        assert!(render_apply_table(&plan).contains(PROVIDER_MATRIX_DOC));
        log.assert_no_mutations();
    }

    // T4 (AC4)
    #[tokio::test]
    async fn invalid_secret_skipped_without_find() {
        let log = CallLog::new();
        let value = "npm_plan_unit_invalid";
        let gha = MockConsumer::new("github-actions")
            .matching(fp(value), ConsumerMatch::by_name("gha:x:NPM_TOKEN"));
        let provider = MockProvider::new("npm")
            .identify_prefix("npm_")
            .validity(Validity::Invalid);
        let plan = plan_for(&[value, "zzz_unknown"], provider, vec![gha], &log).await;
        assert!(plan.rotations.is_empty());
        assert_eq!(plan.skipped[0].reason, "invalid");
        assert_eq!(plan.skipped[0].provider, Some("npm"));
        assert_eq!(plan.skipped[1].reason, "unsupported");
        assert!(log.calls().iter().all(|c| c.method != "find"));
        log.assert_no_mutations();
    }

    // SHA-292: a provider's revoke blocker is a blocker, and stays one when
    // `--check-permissions` recomputes the list.
    #[tokio::test]
    async fn revoke_blocker_survives_recompute() {
        let log = CallLog::new();
        let provider = MockProvider::new("npm").identify_prefix("npm_");
        let mut plan = plan_for(&["npm_plan_unit_revoke_blocker"], provider, vec![], &log).await;
        let r = &mut plan.rotations[0];
        assert_eq!(r.revoke_blocker, None);
        r.revoke_blocker = Some("no operator token".into());
        assert_eq!(blockers(r), ["no operator token"]);
        log.assert_no_mutations();
    }

    #[tokio::test]
    async fn consumer_lookup_error_is_a_blocker() {
        let log = CallLog::new();
        let broken = MockConsumer::new("aws-secrets-manager");
        broken.fail_always("find", ConsumerError::Permanent("403 denied".into()));
        let provider = MockProvider::new("npm").identify_prefix("npm_");
        let plan = plan_for(&["npm_plan_unit_lookup"], provider, vec![broken], &log).await;
        let r = &plan.rotations[0];
        assert_eq!(r.lookup_errors[0].error, "403 denied");
        assert!(r.blockers[0].contains("aws-secrets-manager could not be searched"));
        assert!(render_table(&plan).contains("lookup failed: 403 denied"));
        log.assert_no_mutations();
    }

    /// SHA-294 T4 covers AC4: GitHub rejects Actions secret names starting
    /// with `GITHUB_`, so the convention never offers one; `GH_TOKEN` stays.
    #[test]
    fn github_convention_has_no_github_prefixed_name() {
        let names = consumer_names("github", &ConsumersConfig::default());
        assert!(names.secret.iter().any(|n| n == "GH_TOKEN"));
        assert!(names.all().all(|n| !n.starts_with("GITHUB_")), "{names:?}");
    }

    #[test]
    fn consumer_names_merges_convention_and_config() {
        let mut config = ConsumersConfig::default();
        config.github_actions.secret_names = BTreeMap::from([(
            ProviderName::Aws,
            vec![
                "DEPLOY_SECRET".to_owned(),
                "AWS_SECRET_ACCESS_KEY".to_owned(),
            ],
        )]);
        config.github_actions.key_id_names =
            BTreeMap::from([(ProviderName::Aws, vec!["DEPLOY_KEY_ID".to_owned()])]);
        let names = consumer_names("aws", &config);
        assert_eq!(names.secret, ["AWS_SECRET_ACCESS_KEY", "DEPLOY_SECRET"]);
        assert_eq!(names.key_id, ["AWS_ACCESS_KEY_ID", "DEPLOY_KEY_ID"]);
        assert_eq!(
            consumer_names("github", &config).secret,
            ["GH_TOKEN", "GH_PAT"]
        );
        assert_eq!(consumer_names("npm", &config).secret, ["NPM_TOKEN"]);
        assert_eq!(consumer_names("openai", &config).secret, ["OPENAI_API_KEY"]);
        assert_eq!(consumer_names("other", &config), ConsumerNames::default());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn assign_ids_reuses_open_rotation_and_keeps_later_step() {
        let log = CallLog::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".rotate/state.json");
        let provider = || MockProvider::new("npm").identify_prefix("npm_");
        let values = ["npm_plan_unit_ids_a", "npm_plan_unit_ids_b"];

        let mut first = plan_for(&values, provider(), vec![], &log).await;
        {
            let mut store = StateStore::open(&path).unwrap();
            assign_ids(&mut first, &mut store).unwrap();
        }
        let ids: Vec<String> = first
            .rotations
            .iter()
            .map(|r| r.rotation_id.clone())
            .collect();
        assert!(ids
            .iter()
            .all(|id| id.len() == 12 && id.starts_with("rot-")));
        assert_ne!(ids[0], ids[1]);

        // Move the first rotation on, as apply would.
        {
            let mut store = StateStore::open(&path).unwrap();
            let mut stored = store.get(&ids[0]).unwrap().clone();
            stored.step = Step::Created;
            store.upsert(stored).unwrap();
        }

        let mut second = plan_for(&values, provider(), vec![], &log).await;
        let mut store = StateStore::open(&path).unwrap();
        assign_ids(&mut second, &mut store).unwrap();
        let again: Vec<String> = second
            .rotations
            .iter()
            .map(|r| r.rotation_id.clone())
            .collect();
        assert_eq!(again, ids);
        assert_eq!(second.rotations[0].step, Step::Created);
        assert_eq!(store.get(&ids[0]).unwrap().step, Step::Created);
        assert_eq!(second.rotations[1].step, Step::Planned);
        assert!(render_table(&second).contains("in progress at step created"));
        log.assert_no_mutations();
    }

    /// SHA-294 T2 (AC2), unit half: a re-plan of a rotation at
    /// `pending_revoke` drops the provider warning naming its own
    /// replacement, lists every recorded consumer and shows the recorded
    /// revoke time instead of this run's window.
    #[cfg(unix)]
    #[tokio::test]
    async fn replan_of_pending_revoke_shows_what_was_recorded() {
        let log = CallLog::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".rotate/state.json");
        let provider = || MockProvider::new("npm").identify_prefix("npm_");
        let values = ["npm_plan_unit_replan_pending"];
        let mut first = plan_for(&values, provider(), vec![], &log).await;
        let id = {
            let mut store = StateStore::open(&path).unwrap();
            assign_ids(&mut first, &mut store).unwrap();
            first.rotations[0].rotation_id.clone()
        };
        let now = OffsetDateTime::now_utc();
        {
            let mut store = StateStore::open(&path).unwrap();
            let mut stored = store.get(&id).unwrap().clone();
            stored.step = Step::PendingRevoke;
            stored.replacement_ref = Some("KEYNEW".into());
            stored.revoke_not_before = Some(now + time::Duration::minutes(30));
            stored.consumers = vec![ConsumerState {
                consumer: "aws-secrets-manager".into(),
                consumer_ref: "sm:prod/app".into(),
                status: ConsumerStatus::Updated,
                holds: None,
            }];
            store.upsert(stored).unwrap();
        }

        let mut second = plan_for(&values, provider(), vec![], &log).await;
        second.rotations[0].scope = Some(Scope {
            identity: crate::provider::Identity("user/bot".into()),
            lines: vec![
                "access keys: 2 of 2 used".into(),
                "warning: user bot already has 2 access keys (KEYOLD; KEYNEW)".into(),
                "warning: something else".into(),
            ],
        });
        let mut store = StateStore::open(&path).unwrap();
        assign_ids(&mut second, &mut store).unwrap();
        let r = &second.rotations[0];
        assert_eq!(r.step, Step::PendingRevoke);
        let lines = &r.scope.as_ref().unwrap().lines;
        assert!(!lines.iter().any(|l| l.contains("KEYOLD")), "{lines:?}");
        assert!(lines.contains(&"warning: something else".to_owned()));
        assert!(lines.contains(&format!("replacement: KEYNEW, created by rotation {id}")));

        let table = render_at(&second, "Plan", "", now);
        assert!(!table.contains("already has 2 access keys"), "{table}");
        assert!(table.contains("warning:      something else"), "{table}");
        assert!(
            table.contains("sm:prod/app  recorded  updated (recorded)"),
            "{table}"
        );
        assert!(
            table.contains("(in 30m 0s; recorded by an earlier run)"),
            "{table}"
        );
        assert!(!table.contains("overlap:      0s"), "{table}");
        let json: serde_json::Value = serde_json::from_str(&render_json(&second)).unwrap();
        let recorded = &json["rotations"][0]["recorded"];
        assert_eq!(recorded["consumers"][0]["status"], "updated", "{json}");
        assert!(recorded["revoke_not_before"].is_string(), "{json}");
        // A new rotation has nothing recorded.
        assert!(render_json(&first).contains("\"recorded\": null"));
        log.assert_no_mutations();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn finished_rotation_gets_a_new_id() {
        let log = CallLog::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let value = "npm_plan_unit_finished";
        let mut store = StateStore::open(&path).unwrap();
        let mut done = Rotation::new("rot-00000000", "npm", fp(value));
        done.step = Step::Revoked;
        store.upsert(done).unwrap();

        let provider = MockProvider::new("npm").identify_prefix("npm_");
        let mut plan = plan_for(&[value], provider, vec![], &log).await;
        assign_ids(&mut plan, &mut store).unwrap();
        assert_ne!(plan.rotations[0].rotation_id, "rot-00000000");
        assert_eq!(store.rotations().len(), 2);
    }

    #[tokio::test]
    async fn json_has_stable_top_level_fields() {
        let log = CallLog::new();
        let provider = MockProvider::new("npm").identify_prefix("npm_");
        let plan = plan_for(&["npm_plan_unit_json", "zzz"], provider, vec![], &log).await;
        let json: serde_json::Value = serde_json::from_str(&render_json(&plan)).unwrap();
        assert_eq!(json["version"], 1);
        assert_eq!(json["overlap_window"], "1h");
        assert_eq!(json["rotations"][0]["replacement"]["mode"], "automatic");
        assert_eq!(json["rotations"][0]["state"], "planned");
        assert_eq!(json["skipped"][0]["reason"], "unsupported");
    }

    // SHA-258 (AC7): only a finished, not rolling back, latest rotation
    // makes a finding "already rotated"; duplicates share one entry.
    #[cfg(unix)]
    #[test]
    fn split_already_rotated_uses_the_latest_rotation() {
        let mut providers = ProviderRegistry::new();
        providers.register(Arc::new(MockProvider::new("npm")));
        let (done, rolled, rolling, fresh) = (
            "npm_split_done",
            "npm_split_rolled",
            "npm_split_rolling",
            "npm_split_fresh",
        );
        let at = |s: i64| time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(s);
        let rotation = |id: &str, value: &str, step: Step, when: i64| {
            let mut r = Rotation::new(id, "npm", fp(value));
            r.step = step;
            r.updated_at = at(when);
            r
        };
        let mut rolling_back = rotation("rot-4", rolling, Step::Revoked, 1);
        rolling_back.rollback = Some(crate::state::RollbackProgress::default());
        let rotations = [
            rotation("rot-1", done, Step::Revoked, 1),
            rotation("rot-2", rolled, Step::Revoked, 1),
            rotation("rot-3", rolled, Step::RolledBack, 2),
            rolling_back,
        ];
        let findings = vec![
            finding(done),
            finding(rolled),
            finding(done),
            finding(rolling),
            finding(fresh),
        ];
        let (kept, skipped) = split_already_rotated(findings, &rotations, &providers);
        let kept: Vec<Fingerprint> = kept.iter().map(Finding::fingerprint).collect();
        assert_eq!(kept, [fp(rolled), fp(rolling), fp(fresh)]);
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].fingerprint, fp(done));
        assert_eq!(skipped[0].reason, ALREADY_ROTATED);
        assert_eq!(skipped[0].provider, Some("npm"));
        assert_eq!(skipped[0].sources.len(), 2);
        assert_eq!(
            skipped[0].detail.as_deref(),
            Some("rotation rot-1 already rotated on 1970-01-01T00:00:01Z; nothing to do")
        );
    }

    // SHA-289: a secret skipped as invalid whose rotation waits for a
    // revoke by hand is marked, with the rotation's id; others are not.
    #[cfg(unix)]
    #[tokio::test]
    async fn invalid_secret_of_a_revoke_manual_rotation_is_revoked_by_hand() {
        let log = CallLog::new();
        let waiting = "npm_plan_unit_by_hand";
        let other = "npm_plan_unit_plain_invalid";
        let mut by_hand = Rotation::new("rot-11111111", "npm", fp(waiting));
        by_hand.step = Step::RevokeManual;
        let mut rolling = Rotation::new("rot-22222222", "npm", fp(other));
        rolling.step = Step::RevokeManual;
        rolling.rollback = Some(crate::state::RollbackProgress::default());

        let provider = MockProvider::new("npm")
            .identify_prefix("npm_")
            .validity(Validity::Invalid);
        let mut plan = plan_for(&[waiting, other], provider, vec![], &log).await;
        mark_revoked_by_hand(&mut plan, &[by_hand, rolling]);
        let first = plan
            .skipped
            .iter()
            .find(|s| s.fingerprint == fp(waiting))
            .unwrap();
        assert_eq!(first.reason, REVOKED_BY_HAND);
        assert_eq!(first.rotation_id.as_deref(), Some("rot-11111111"));
        assert!(first.detail.as_deref().unwrap().contains("rot-11111111"));
        let second = plan
            .skipped
            .iter()
            .find(|s| s.fingerprint == fp(other))
            .unwrap();
        assert_eq!(second.reason, "invalid");
        assert_eq!(second.rotation_id, None);
        let json: serde_json::Value = serde_json::from_str(&render_json(&plan)).unwrap();
        assert!(json["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["reason"] == "revoked by hand"));
        assert!(render_table(&plan).contains("revoked by hand"));
        assert_eq!(
            resume_text(Step::RevokeManual),
            "the old secret must be deleted by hand; rotate apply records it revoked once it no longer works"
        );
        log.assert_no_mutations();
    }
}
