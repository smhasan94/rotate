# Renders the job summary of the rotate GitHub Action in apply mode
# (SHA-338) as GitHub flavored Markdown. Run by action/run.sh with
# `jq -n -r`:
#
#   $rows        [] or [the `rotate --json status --all` array]
#   $confirm     the confirm input: rotation ids, comma-separated
#   $exit_code   rotate apply's exit code
#   $overlap     the overlap window apply used, such as 1h ("" if unknown)
#   $max_wait    the max-wait input
#   $repository  owner/repo
#   $alerts      the alert-number input ("" in poll mode)
#   $mode        "numbers" or "list"
#   $server      GITHUB_SERVER_URL, for alert links
#   $run_url     this workflow run, or ""
#   $notes       rotate's `warning:`, `error:` and `note:` lines
#
# Every value comes from rotate's output and the state file, which hold
# fingerprints and references only, never a secret value.

# A Markdown table cell: one line, no pipe, no raw HTML.
def cell: tostring | gsub("[\r\n]+"; " ") | gsub("\\|"; "\\|") | gsub("<"; "&lt;");

def code: "`" + (tostring | gsub("`"; "'")) + "`";

($confirm | split(",")) as $ids
| [($rows[0] // [])[] | select(.rotation_id as $id | $ids | index($id))] as $shown
| ([$shown[] | .revoke_not_before // empty] | max) as $revoke_at
| [$notes | split("\n")[] | select(length > 0)] as $lines
| [
    "## rotate apply: \($repository | cell)",
    "",
    (if $mode == "numbers"
     then "Alerts: " + ([$alerts | split(",")[] | "[#\(.)](\($server)/\($repository)/security/secret-scanning/\(.))"] | join(", "))
     else "Alerts: the open alerts of the six supported secret types (first 100)."
     end)
    + (if $run_url != "" then " · [Workflow run](\($run_url))" else "" end),
    "",
    "Confirmed: " + ([$ids[] | code] | join(", ")) + ".",
    "",
    (if $exit_code == "0" then
       "**Done.** Every confirmed rotation finished: the replacement is in every consumer, verified, and the old secret is revoked."
     elif $exit_code == "1" then
       "**Failed: the old secret is still valid.** rotate stopped before revoking it. The step and error of each rotation are below; the audit log has every step. Re-run `rotate apply` with the state file once the cause is fixed, or `rotate rollback`."
     elif $exit_code == "3" then
       "**Not revoked: the overlap window is longer than this job may wait.** The replacement is in every consumer and verified; the old secret is still valid. The overlap window"
       + (if $overlap != "" then " (\($overlap | code))" else "" end)
       + " ends at \($revoke_at // "an unknown time" | code), later than `max-wait` (\($max_wait | code)) allows."
       + " After that time, revoke the old secret: run `rotate apply` again with the state file from the audit artifact, or delete it at the provider by hand."
     elif $exit_code == "4" then
       "**Revoke by hand.** The replacement is in every consumer and verified, but rotate cannot revoke the old secret. Do this, then run `rotate apply` again with the state file from the audit artifact to record it:"
     elif $exit_code == "2" then
       "**Nothing was changed.** rotate apply exited with code 2:"
     else
       "**rotate apply exited with code \($exit_code | cell).**"
     end),
    "",
    (if $exit_code == "4" then
       ($shown[] | select(.step == "revoke_manual") | "- \(.rotation_id | code): \(.hint | cell)"),
       ""
     else empty end),
    (if ($exit_code != "0" and $exit_code != "1" and $exit_code != "3" and $exit_code != "4") and ($lines | length) > 0 then
       ($lines[] | "- \(cell)"),
       ""
     else empty end),
    (if ($shown | length) > 0 then
       "### Rotations",
       "",
       "| Rotation | Provider | Fingerprint | Step | Consumers updated | Revoke not before | Next | Error |",
       "|---|---|---|---|---|---|---|---|",
       ($shown[] |
         "| \(.rotation_id | code) | \(.provider | cell) | \(.fingerprint | code) | \(.step | cell) | "
         + "\(.consumers_updated)/\(.consumers_total) | \(.revoke_not_before // "none" | cell) | \(.hint | cell) | "
         + "\(if .error then "\(.error.step | cell): \(.error.text | cell)" else "none" end) |"),
       ""
     else empty end),
    (if ($exit_code == "0" or $exit_code == "1" or $exit_code == "3" or $exit_code == "4") and ($lines | length) > 0 then
       "### Notes",
       "",
       ($lines[] | "- \(cell)"),
       ""
     else empty end),
    "The audit log and state file of this run are under `.rotate/` in the state directory (fingerprints only)."
  ]
| .[]
