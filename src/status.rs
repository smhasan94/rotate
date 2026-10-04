//! `rotate status` (SHA-263, FR19, US7): what is in progress, what waits
//! for its overlap window, and what failed and needs attention.
//!
//! Everything here is a pure function of the state file snapshot, the audit
//! log entries and a clock. No provider, consumer or network type appears in
//! any signature, so status cannot make a call: it reads two local files and
//! prints.
//!
//! A row is shown by default while the rotation is unfinished (any step but
//! `revoked` and `rolled_back`) or while a rollback of it is in progress;
//! `--all` adds the finished ones. A rotation is *pending* (exit 3) at
//! `created`, `consumers_updated`, `verified`, `pending_revoke`, `failed`,
//! `needs_rollback` or `revoke_manual` (SHA-289), or while it is being
//! rolled back. `planned` is listed
//! but not pending: nothing has changed for it yet.
//!
//! The only free text printed is the error of a rotation's last audit
//! entry, a [`RedactedText`] that was redacted again when it was read back,
//! and the revoke-by-hand instructions the provider gave (SHA-289), which
//! were redacted before they were stored.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

use crate::audit::{AuditEntry, AuditError, AuditStep, RedactedText};
use crate::secret::Fingerprint;
use crate::state::{ConsumerStatus, Rotation, StateSnapshot, Step};

/// The error of a rotation's last audit entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LastError {
    /// The step the entry records.
    pub step: AuditStep,
    /// When it was written.
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    /// The error, redacted.
    pub text: RedactedText,
    /// The entry's outcome (`failed` or `skipped`). Not in the JSON.
    #[serde(skip)]
    pub outcome: crate::audit::Outcome,
}

impl LastError {
    /// True for the `skipped` revoke entry apply writes when it records
    /// a pending revoke (SHA-294): it means waiting for the overlap
    /// window, not a failure. Only meaningful while the rotation is at
    /// `pending_revoke`; the row's hint says when the revoke is due.
    fn is_waiting(&self, rotation: &Rotation) -> bool {
        rotation.step == Step::PendingRevoke
            && self.step == AuditStep::Revoke
            && self.outcome == crate::audit::Outcome::Skipped
    }
}

/// The last audit entry of each rotation, kept only when it has an error
/// and its outcome is not `ok` (an `ok` entry's text is a detail, such as
/// a revoke by hand being confirmed), plus one warning per kind of
/// unreadable line. A bad line never stops
/// status; it is skipped and reported.
pub fn last_errors(
    entries: impl IntoIterator<Item = Result<AuditEntry, AuditError>>,
) -> (BTreeMap<String, LastError>, Vec<String>) {
    let mut last: BTreeMap<String, AuditEntry> = BTreeMap::new();
    let mut bad = 0usize;
    let mut first_bad = None;
    for entry in entries {
        match entry {
            Ok(entry) => {
                last.insert(entry.rotation_id.clone(), entry);
            }
            Err(err) => {
                bad += 1;
                first_bad.get_or_insert_with(|| err.to_string());
            }
        }
    }
    let errors = last
        .into_iter()
        .filter(|(_, entry)| entry.outcome != crate::audit::Outcome::Ok)
        .filter_map(|(id, entry)| {
            entry.error.map(|text| {
                (
                    id,
                    LastError {
                        step: entry.step,
                        at: entry.ts,
                        text,
                        outcome: entry.outcome,
                    },
                )
            })
        })
        .collect();
    let warnings = first_bad
        .map(|first| {
            vec![format!(
                "{bad} audit log line(s) could not be read and were skipped (first: {first})"
            )]
        })
        .unwrap_or_default();
    (errors, warnings)
}

/// One row of `rotate status`, as the table and `--json` show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusRow {
    /// Rotation id.
    pub rotation_id: String,
    /// Provider name.
    pub provider: String,
    /// Fingerprint of the secret being rotated.
    pub fingerprint: Fingerprint,
    /// Step reached.
    pub step: Step,
    /// A rollback has started and not finished.
    pub rollback_in_progress: bool,
    /// When the rotation was last recorded.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    /// Seconds from `updated_at` to now, never negative.
    pub updated_seconds_ago: i64,
    /// Consumers with status `updated`.
    pub consumers_updated: usize,
    /// Every consumer recorded.
    pub consumers_total: usize,
    /// Earliest revoke time, as recorded.
    #[serde(with = "time::serde::rfc3339::option")]
    pub revoke_not_before: Option<OffsetDateTime>,
    /// Seconds until `revoke_not_before` (0 once passed), for
    /// `pending_revoke` only.
    pub revoke_remaining_seconds: Option<i64>,
    /// The step that failed or could not continue.
    pub failed_step: Option<AuditStep>,
    /// Counts toward exit code 3.
    pub pending: bool,
    /// What to do next.
    pub hint: String,
    /// The last audit entry's error, if it has one.
    pub error: Option<LastError>,
}

/// True when the rotation needs someone to act or wait: see the module doc.
pub fn is_pending(rotation: &Rotation) -> bool {
    rotation.is_rolling_back()
        || matches!(
            rotation.step,
            Step::Created
                | Step::ConsumersUpdated
                | Step::Verified
                | Step::PendingRevoke
                | Step::Failed
                | Step::NeedsRollback
                | Step::RevokeManual
        )
}

/// True when status lists the rotation without `--all`.
pub fn is_shown_by_default(rotation: &Rotation) -> bool {
    rotation.is_in_progress() || rotation.is_rolling_back()
}

/// True when any rotation in the snapshot is pending, shown or not.
pub fn any_pending(snapshot: &StateSnapshot) -> bool {
    snapshot.rotations().iter().any(is_pending)
}

/// The rows to show, sorted by rotation id. `errors` comes from
/// [`last_errors`]; `now` is the clock status runs with.
pub fn rows(
    snapshot: &StateSnapshot,
    errors: &BTreeMap<String, LastError>,
    now: OffsetDateTime,
    all: bool,
) -> Vec<StatusRow> {
    snapshot
        .rotations()
        .iter()
        .filter(|r| all || is_shown_by_default(r))
        .map(|r| {
            let error = errors
                .get(&r.rotation_id)
                .filter(|e| !e.is_waiting(r))
                .cloned();
            row(r, error, now)
        })
        .collect()
}

fn row(rotation: &Rotation, error: Option<LastError>, now: OffsetDateTime) -> StatusRow {
    let remaining = match (rotation.step, rotation.revoke_not_before) {
        (Step::PendingRevoke, Some(at)) => Some((at - now).whole_seconds().max(0)),
        _ => None,
    };
    StatusRow {
        rotation_id: rotation.rotation_id.clone(),
        provider: rotation.provider.clone(),
        fingerprint: rotation.fingerprint.clone(),
        step: rotation.step,
        rollback_in_progress: rotation.is_rolling_back(),
        updated_at: rotation.updated_at,
        updated_seconds_ago: (now - rotation.updated_at).whole_seconds().max(0),
        consumers_updated: rotation
            .consumers
            .iter()
            .filter(|c| c.status == ConsumerStatus::Updated)
            .count(),
        consumers_total: rotation.consumers.len(),
        revoke_not_before: rotation.revoke_not_before,
        revoke_remaining_seconds: remaining,
        failed_step: rotation.failed_step,
        pending: is_pending(rotation),
        hint: hint(rotation, now),
        error,
    }
}

/// What to do next for `rotation`, one line.
pub fn hint(rotation: &Rotation, now: OffsetDateTime) -> String {
    if rotation.is_rolling_back() {
        return "rollback in progress: re-run `rotate rollback` with the same input to finish it"
            .to_owned();
    }
    let next = "see the audit log, then re-run `rotate apply` or run `rotate rollback`";
    match rotation.step {
        Step::Planned => "not started: run `rotate apply` to start it".to_owned(),
        Step::Created | Step::ConsumersUpdated | Step::Verified => {
            "interrupted: re-run `rotate apply` with the same input to resume".to_owned()
        }
        Step::PendingRevoke => match rotation.revoke_not_before {
            Some(at) if now < at => format!(
                "re-run `rotate apply` after {} to revoke the old secret",
                clock_time(at, now)
            ),
            _ => "overlap window over: re-run `rotate apply` to revoke the old secret".to_owned(),
        },
        Step::Failed => {
            let consumer = rotation
                .consumers
                .iter()
                .find(|c| c.status == ConsumerStatus::Failed);
            match (consumer, rotation.failed_step) {
                (Some(c), _) => format!("consumer {} failed: {next}", c.consumer_ref),
                (None, Some(step)) => format!("failed at {}: {next}", name(&step)),
                (None, None) => format!("failed: {next}"),
            }
        }
        Step::NeedsRollback => {
            "run `rotate rollback` with the same input, then `rotate apply` again".to_owned()
        }
        Step::RevokeManual => format!(
            "revoke by hand: {}; then re-run `rotate apply` to record it",
            crate::apply::by_hand_text(
                rotation
                    .revoke_instructions
                    .as_deref()
                    .unwrap_or("delete the old secret at the provider")
            )
        ),
        Step::Revoked => "done".to_owned(),
        // SHA-290: the restored consumers hold a revoked secret.
        Step::RolledBack
            if rotation
                .rollback
                .as_ref()
                .is_some_and(|p| p.old_still_revoked) =>
        {
            "rolled back; the old secret stays revoked: create a new credential and run `rotate apply`"
                .to_owned()
        }
        Step::RolledBack => "rolled back".to_owned(),
    }
}

/// The snake_case JSON name of a step or audit step.
fn name(value: &impl Serialize) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(s)) => s,
        _ => "unknown".to_owned(),
    }
}

/// `07:12:00 UTC`, with the date in front when it is not `now`'s UTC date.
fn clock_time(at: OffsetDateTime, now: OffsetDateTime) -> String {
    let at = at.to_offset(UtcOffset::UTC);
    let time = format!("{:02}:{:02}:{:02} UTC", at.hour(), at.minute(), at.second());
    if at.date() == now.to_offset(UtcOffset::UTC).date() {
        time
    } else {
        format!("{} {time}", at.date())
    }
}

/// `45s`, `9m 59s`, `1h 5m`, `3d 4h`.
fn duration_text(secs: i64) -> String {
    let secs = secs.max(0);
    if secs >= 86_400 {
        return format!("{}d {}h", secs / 86_400, secs / 3600 % 24);
    }
    crate::apply::remaining_text(time::Duration::seconds(secs))
}

fn step_text(row: &StatusRow) -> String {
    if row.rollback_in_progress {
        format!("rolling_back ({})", name(&row.step))
    } else {
        name(&row.step)
    }
}

fn revoke_text(row: &StatusRow, now: OffsetDateTime) -> String {
    match (row.revoke_remaining_seconds, row.revoke_not_before) {
        (Some(0), Some(at)) => format!("{} (due)", clock_time(at, now)),
        (Some(left), Some(at)) => format!("{} (in {})", clock_time(at, now), duration_text(left)),
        _ => "-".to_owned(),
    }
}

/// The human-readable table. `total` is the number of rotations in the
/// state file, so an empty table can say how many finished ones it hides.
pub fn render_table(rows: &[StatusRow], total: usize, now: OffsetDateTime) -> String {
    if total == 0 {
        return "no rotations\n".to_owned();
    }
    if rows.is_empty() {
        return format!("no rotations in progress ({total} finished; use --all to show them)\n");
    }
    let header = [
        "ROTATION",
        "PROVIDER",
        "FINGERPRINT",
        "STEP",
        "UPDATED",
        "CONSUMERS",
        "REVOKE AFTER",
        "HINT",
    ]
    .map(str::to_owned);
    let cells: Vec<[String; 8]> = rows
        .iter()
        .map(|r| {
            [
                r.rotation_id.clone(),
                r.provider.clone(),
                r.fingerprint.to_string(),
                step_text(r),
                format!("{} ago", duration_text(r.updated_seconds_ago)),
                format!("{}/{}", r.consumers_updated, r.consumers_total),
                revoke_text(r, now),
                r.hint.clone(),
            ]
        })
        .collect();
    let mut widths = header.clone().map(|h| h.len());
    for row in &cells {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.len());
        }
    }
    let line = |cells: &[String; 8]| {
        let mut text = String::new();
        for (cell, width) in cells.iter().zip(widths) {
            let _ = write!(text, "{cell:<width$}  ");
        }
        let mut text = text.trim_end().to_owned();
        text.push('\n');
        text
    };
    let mut out = line(&header);
    for (row, cells) in rows.iter().zip(&cells) {
        out.push_str(&line(cells));
        if let Some(error) = &row.error {
            let when = error
                .at
                .format(&Rfc3339)
                .unwrap_or_else(|_| error.at.to_string());
            let _ = writeln!(
                out,
                "  last error ({}, {when}): {}",
                name(&error.step),
                error.text
            );
        }
    }
    out
}

/// `--json`: an array of rows, as documented in `docs/status-schema.json`.
pub fn render_json(rows: &[StatusRow]) -> String {
    serde_json::to_string_pretty(rows).unwrap_or_else(|_| "[]".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{ConsumerState, RollbackProgress};
    use time::Duration;

    fn now() -> OffsetDateTime {
        OffsetDateTime::parse("2026-10-02T07:07:00Z", &Rfc3339).unwrap()
    }

    fn rotation(id: &str, step: Step) -> Rotation {
        let mut r = Rotation::new(id, "aws", Fingerprint::of(id.as_bytes()));
        r.step = step;
        r.updated_at = now() - Duration::minutes(3);
        r.consumers = vec![
            ConsumerState {
                consumer: "github-actions".into(),
                consumer_ref: "gha:o/r:X".into(),
                status: ConsumerStatus::Updated,
                holds: None,
            },
            ConsumerState {
                consumer: "aws-secrets-manager".into(),
                consumer_ref: "sm:prod/app".into(),
                status: ConsumerStatus::Updated,
                holds: None,
            },
        ];
        r
    }

    fn snapshot(rotations: Vec<Rotation>) -> StateSnapshot {
        let dir = tempfile::tempdir().unwrap();
        let mut store = crate::state::StateStore::open(dir.path().join("state.json")).unwrap();
        for r in rotations {
            store.upsert(r).unwrap();
        }
        store.snapshot().clone()
    }

    #[test]
    fn pending_revoke_row_and_hint() {
        let mut r = rotation("rot-1", Step::PendingRevoke);
        r.revoke_not_before = Some(now() + Duration::minutes(5));
        let row = row(&r, None, now());
        assert_eq!(row.revoke_remaining_seconds, Some(300));
        assert!(row.pending);
        assert_eq!(
            row.hint,
            "re-run `rotate apply` after 07:12:00 UTC to revoke the old secret"
        );
        assert_eq!(revoke_text(&row, now()), "07:12:00 UTC (in 5m 0s)");
        assert_eq!(row.updated_seconds_ago, 180);

        r.revoke_not_before = Some(now() + Duration::days(1));
        assert!(hint(&r, now()).contains("after 2026-10-03 07:07:00 UTC"));
        r.revoke_not_before = Some(now() - Duration::seconds(1));
        assert_eq!(
            hint(&r, now()),
            "overlap window over: re-run `rotate apply` to revoke the old secret"
        );
        let row = super::row(&r, None, now());
        assert_eq!(row.revoke_remaining_seconds, Some(0));
        assert!(revoke_text(&row, now()).ends_with("(due)"));
    }

    #[test]
    fn every_step_has_a_hint_and_pending_flag() {
        let cases = [
            (Step::Planned, false, true, "not started"),
            (Step::Created, true, true, "interrupted"),
            (Step::ConsumersUpdated, true, true, "interrupted"),
            (Step::Verified, true, true, "interrupted"),
            (Step::PendingRevoke, true, true, "overlap window over"),
            (Step::Failed, true, true, "failed: see the audit log"),
            (Step::NeedsRollback, true, true, "run `rotate rollback`"),
            (Step::Revoked, false, false, "done"),
            (Step::RolledBack, false, false, "rolled back"),
        ];
        for (step, pending, shown, text) in cases {
            let r = rotation("rot-1", step);
            assert_eq!(is_pending(&r), pending, "{step:?}");
            assert_eq!(is_shown_by_default(&r), shown, "{step:?}");
            assert!(
                hint(&r, now()).starts_with(text),
                "{step:?}: {}",
                hint(&r, now())
            );
        }
    }

    #[test]
    fn failed_hint_names_consumer_or_step() {
        let mut r = rotation("rot-1", Step::Failed);
        r.failed_step = Some(AuditStep::Verify);
        assert!(hint(&r, now()).starts_with("failed at verify: "));
        r.consumers[1].status = ConsumerStatus::Failed;
        assert!(hint(&r, now()).starts_with("consumer sm:prod/app failed: see the audit log"));
        assert_eq!(super::row(&r, None, now()).consumers_updated, 1);
    }

    #[test]
    fn rollback_in_progress_is_shown_and_pending_at_any_step() {
        let mut r = rotation("rot-1", Step::Revoked);
        r.rollback = Some(RollbackProgress::default());
        assert!(is_pending(&r));
        assert!(is_shown_by_default(&r));
        assert!(hint(&r, now()).starts_with("rollback in progress"));
        let row = super::row(&r, None, now());
        assert_eq!(step_text(&row), "rolling_back (revoked)");
        r.step = Step::RolledBack;
        assert!(!is_pending(&r));
        assert!(!is_shown_by_default(&r));
        assert_eq!(hint(&r, now()), "rolled back");
        // SHA-290: the hint says the old secret stays revoked; still done.
        r.rollback.as_mut().unwrap().old_still_revoked = true;
        assert!(!is_pending(&r));
        assert!(!is_shown_by_default(&r));
        assert_eq!(
            hint(&r, now()),
            "rolled back; the old secret stays revoked: create a new credential and run `rotate apply`"
        );
    }

    #[test]
    fn rows_filter_and_table() {
        let snap = snapshot(vec![
            rotation("rot-a", Step::Revoked),
            rotation("rot-b", Step::Failed),
        ]);
        assert!(any_pending(&snap));
        let errors = BTreeMap::new();
        let shown = rows(&snap, &errors, now(), false);
        assert_eq!(shown.len(), 1);
        assert_eq!(rows(&snap, &errors, now(), true).len(), 2);
        let table = render_table(&shown, 2, now());
        let mut lines = table.lines();
        assert!(lines.next().unwrap().starts_with("ROTATION  PROVIDER"));
        assert!(lines.next().unwrap().starts_with("rot-b"));

        assert_eq!(render_table(&[], 0, now()), "no rotations\n");
        assert_eq!(
            render_table(&[], 3, now()),
            "no rotations in progress (3 finished; use --all to show them)\n"
        );
        assert_eq!(render_json(&[]), "[]");
        assert!(!any_pending(&snapshot(vec![rotation(
            "rot-a",
            Step::Planned
        )])));
    }

    fn entry(id: &str, step: AuditStep, error: Option<&str>) -> AuditEntry {
        AuditEntry {
            version: 1,
            ts: now(),
            actor: "ci@runner".into(),
            rotation_id: id.into(),
            provider: "aws".into(),
            fingerprint: Fingerprint::of(id.as_bytes()),
            replacement_fingerprint: None,
            consumer: None,
            replacement_mode: None,
            scope_widened: None,
            action: None,
            step,
            outcome: if error.is_some() {
                crate::audit::Outcome::Failed
            } else {
                crate::audit::Outcome::Ok
            },
            error: error.map(RedactedText::new),
        }
    }

    #[test]
    fn last_errors_keeps_only_a_last_entry_with_an_error() {
        let (errors, warnings) = last_errors(vec![
            Ok(entry("rot-1", AuditStep::Check, Some("old"))),
            Ok(entry("rot-1", AuditStep::Create, None)),
            Ok(entry("rot-2", AuditStep::Create, None)),
            Ok(entry("rot-2", AuditStep::Update, Some("denied"))),
        ]);
        assert!(warnings.is_empty());
        assert_eq!(errors.len(), 1);
        assert_eq!(errors["rot-2"].text.as_str(), "denied");
        assert_eq!(errors["rot-2"].step, AuditStep::Update);

        let mut r = rotation("rot-2", Step::Failed);
        r.failed_step = Some(AuditStep::Update);
        let row = super::row(&r, errors.get("rot-2").cloned(), now());
        let table = render_table(&[row], 1, now());
        assert!(
            table.contains("\n  last error (update, 2026-10-02T07:07:00Z): denied\n"),
            "{table}"
        );
    }

    #[test]
    fn unreadable_audit_lines_become_one_warning() {
        let bad = || {
            Err(AuditError::Corrupt {
                path: "a.jsonl".into(),
                line: 2,
                reason: "malformed JSON".into(),
            })
        };
        let (errors, warnings) = last_errors(vec![
            bad(),
            Ok(entry("rot-1", AuditStep::Update, Some("x"))),
            bad(),
        ]);
        assert_eq!(errors.len(), 1);
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].starts_with("2 audit log line(s)"),
            "{warnings:?}"
        );
    }

    #[test]
    fn json_row_fields() {
        let mut r = rotation("rot-1", Step::PendingRevoke);
        r.revoke_not_before = Some(now() + Duration::minutes(5));
        let json: serde_json::Value =
            serde_json::from_str(&render_json(&[super::row(&r, None, now())])).unwrap();
        let row = &json[0];
        assert_eq!(row["step"], "pending_revoke");
        assert_eq!(row["revoke_not_before"], "2026-10-02T07:12:00Z");
        assert_eq!(row["revoke_remaining_seconds"], 300);
        assert_eq!(row["updated_at"], "2026-10-02T07:04:00Z");
        assert_eq!(row["failed_step"], serde_json::Value::Null);
        assert_eq!(row["error"], serde_json::Value::Null);
    }

    #[test]
    fn durations() {
        assert_eq!(duration_text(45), "45s");
        assert_eq!(duration_text(599), "9m 59s");
        assert_eq!(duration_text(3900), "1h 5m");
        assert_eq!(duration_text(3 * 86_400 + 4 * 3600), "3d 4h");
        assert_eq!(duration_text(-5), "0s");
    }

    // SHA-289 T10 (AC10)
    #[test]
    fn revoke_manual_is_pending_with_the_instructions_as_hint() {
        let mut r = rotation("rot-m", Step::RevokeManual);
        r.revoke_instructions = Some(crate::provider::openai::REVOKE_NEEDS_ADMIN.into());
        assert!(is_pending(&r));
        assert!(is_shown_by_default(&r));
        assert!(any_pending(&snapshot(vec![r.clone()])));
        assert_eq!(
            hint(&r, now()),
            "revoke by hand: without an Admin API key rotate cannot delete OpenAI keys; delete it at https://platform.openai.com/api-keys; then re-run `rotate apply` to record it"
        );
        let row = super::row(&r, None, now());
        let table = render_table(std::slice::from_ref(&row), 1, now());
        assert!(table.contains("revoke_manual"), "{table}");
        let json: serde_json::Value = serde_json::from_str(&render_json(&[row])).unwrap();
        assert_eq!(json[0]["step"], "revoke_manual");
        assert_eq!(json[0]["pending"], true);

        r.revoke_instructions = None;
        assert!(hint(&r, now()).starts_with("revoke by hand: delete the old secret"));
    }

    // An ok entry's text (a revoke by hand confirmed) is not an error.
    #[test]
    fn ok_entry_text_is_not_an_error() {
        let mut confirmed = entry("rot-1", AuditStep::Revoke, None);
        confirmed.error = Some(RedactedText::new(
            "revoked by hand, confirmed by check_valid",
        ));
        let (errors, _) = last_errors(vec![
            Ok(entry("rot-1", AuditStep::Revoke, Some("old"))),
            Ok(confirmed),
        ]);
        assert!(errors.is_empty(), "{errors:?}");
    }
    /// SHA-294 T3 (AC3): the skipped revoke entry that records an open
    /// overlap window is not a last error at `pending_revoke`; the hint
    /// says when the revoke is due. A revoke that failed still shows.
    #[test]
    fn waiting_revoke_is_a_hint_not_a_last_error() {
        let mut waiting = entry("rot-w", AuditStep::Revoke, None);
        waiting.outcome = crate::audit::Outcome::Skipped;
        waiting.error = Some(RedactedText::new(
            "overlap window open until 2026-10-02T07:12:00Z",
        ));
        let failed = entry("rot-f", AuditStep::Revoke, Some("revoke refused"));
        let (errors, _) = last_errors(vec![Ok(waiting), Ok(failed)]);
        assert_eq!(errors.len(), 2, "last_errors itself keeps both");

        let mut pending = rotation("rot-w", Step::PendingRevoke);
        pending.revoke_not_before = Some(now() + Duration::minutes(5));
        let mut broken = rotation("rot-f", Step::Failed);
        broken.failed_step = Some(AuditStep::Revoke);
        let snap = snapshot(vec![pending, broken]);
        let shown = rows(&snap, &errors, now(), false);
        let by_id = |id: &str| shown.iter().find(|r| r.rotation_id == id).unwrap();
        assert_eq!(by_id("rot-w").error, None);
        assert!(
            by_id("rot-w").hint.contains("after 07:12:00 UTC"),
            "{:?}",
            by_id("rot-w")
        );
        assert_eq!(
            by_id("rot-f").error.as_ref().unwrap().text.as_str(),
            "revoke refused"
        );
        let table = render_table(&shown, 2, now());
        assert!(!table.contains("overlap window open"), "{table}");
        assert!(
            table.contains("last error (revoke, 2026-10-02T07:07:00Z): revoke refused"),
            "{table}"
        );
        let json = render_json(&shown);
        assert!(!json.contains("overlap window open"), "{json}");

        // The same skipped entry on a rotation no longer pending revoke
        // (a hold, say) is still shown.
        let mut held = entry("rot-h", AuditStep::Revoke, None);
        held.outcome = crate::audit::Outcome::Skipped;
        held.error = Some(RedactedText::new(
            "consumer x does not hold the replacement",
        ));
        let (errors, _) = last_errors(vec![Ok(held)]);
        let snap = snapshot(vec![rotation("rot-h", Step::Verified)]);
        assert!(rows(&snap, &errors, now(), false)[0].error.is_some());
    }
}
