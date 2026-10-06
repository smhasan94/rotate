# Renders the job summary of the rotate GitHub Action (SHA-198) as GitHub
# flavored Markdown. Run by action/run.sh with `jq -n -r`:
#
#   $plans       [] or [the `rotate plan --json` document]
#   $repository  owner/repo
#   $alerts      the alert-number input ("" in poll mode)
#   $mode        "numbers" or "list"
#   $server      GITHUB_SERVER_URL, for alert links
#   $run_url     this workflow run, or ""
#   $notes       rotate's `warning:` and `error:` lines, one per line
#   $exit_code   rotate's exit code
#
# Every value comes from rotate's output, which holds fingerprints and
# references only, never a secret value.

# A Markdown table cell: one line, no pipe, no raw HTML.
def cell: tostring | gsub("[\r\n]+"; " ") | gsub("\\|"; "\\|") | gsub("<"; "&lt;");

def code: "`" + (tostring | gsub("`"; "'")) + "`";

# The alert page URL of a plan source `<html_url>[:line][@commit]`.
def source_url: capture("^(?<url>.*?)(?::[0-9]+)?(?:@[0-9A-Za-z]+)?$").url;

def alert_link($url):
  (($url | capture("/security/secret-scanning/(?<n>[0-9]+)$") | .n)? // null) as $n
  | if $n then "[#\($n)](\($url | cell))" else ($url | cell) end;

def alert_cell: [.sources[]? | source_url | alert_link(.)] | unique | if . == [] then "unknown" else join("<br>") end;

def consumer_cell:
  ([.consumers[]? |
      "\(.consumer_ref | code) (\(.consumer | cell), \(.match_method | cell)): "
      + (if .updatable then "updatable" else "not updatable: \(.reason // "no reason given" | cell)" end)]
   + [.lookup_errors[]? | "\(.consumer | cell): lookup failed: \(.error | cell)"])
  | if . == [] then "none found" else join("<br>") end;

def blocker_cell: [.blockers[]? | cell] | if . == [] then "none" else join("<br>") end;

# `warning: github-alert line N skipped: alert #M <reason>` from the parser.
def alert_skips:
  [$notes | split("\n")[]
   | capture("^warning: github-alert line [0-9]+ skipped: alert #(?<n>[0-9]+) (?<detail>.*)$")?];

def skip_reason:
  if test("^is resolved") then "resolved"
  elif test("no `secret` field") then "no secret"
  elif test("base64") then "bad base64"
  else "skipped" end;

def other_notes:
  [$notes | split("\n")[] | select(length > 0)
   | select(test("^warning: github-alert line [0-9]+ skipped: alert #[0-9]+ ") | not)];

($plans[0] // null) as $plan
| alert_skips as $alert_skips
| ($plan.rotations // []) as $rotations
| ($plan.skipped // []) as $skipped
| other_notes as $other
| [
    "## rotate plan: \($repository | cell)",
    "",
    (if $mode == "numbers"
     then "Alerts: " + ([$alerts | split(",")[] | "[#\(.)](\($server)/\($repository)/security/secret-scanning/\(.))"] | join(", "))
     else "Alerts: the open alerts of the six supported secret types (first 100)."
     end)
    + (if $run_url != "" then " · [Workflow run](\($run_url))" else "" end),
    "",
    (if $plan == null then
       "rotate exited with code \($exit_code) and wrote no plan:",
       "",
       ($other[] | "- \(cell)"),
       ""
     elif ($rotations | length) == 0 and ($skipped | length) == 0 and ($alert_skips | length) == 0 then
       (if $mode == "list"
        then "No open secret-scanning alerts of the supported types."
        else "Nothing to rotate in these alerts."
        end),
       ""
     else
       "\($rotations | length) to rotate, \(($skipped | length) + ($alert_skips | length)) skipped.",
       ""
     end),
    (if ($rotations | length) > 0 then
       "### Rotations",
       "",
       "| Rotation | Alert | Provider | Fingerprint | Scope | Consumers | Replacement | Revoke | Blockers |",
       "|---|---|---|---|---|---|---|---|---|",
       ($rotations[] |
         "| \(.rotation_id | code) | \(alert_cell) | \(.provider | cell) | \(.fingerprint | code) | "
         + "\(if .scope then (.scope.identity | cell) else "unknown: \(.scope_error // "not described" | cell)" end) | "
         + "\(consumer_cell) | \(.replacement.mode | cell) | \(.revoke_action | cell) | \(blocker_cell) |"),
       ""
     else empty end),
    (if ($skipped | length) + ($alert_skips | length) > 0 then
       "### Skipped",
       "",
       "| Alert | Provider | Fingerprint | Reason | Detail |",
       "|---|---|---|---|---|",
       ($alert_skips[] |
         "| [#\(.n)](\($server)/\($repository)/security/secret-scanning/\(.n)) | none | none | \(.detail | skip_reason) | alert #\(.n) \(.detail | cell) |"),
       ($skipped[] |
         "| \(alert_cell) | \(.provider // "none" | cell) | \(.fingerprint | code) | \(.reason | cell) | \(.detail // "" | cell) |"),
       ""
     else empty end),
    (if $plan != null and ($other | length) > 0 then
       "### Warnings",
       "",
       ($other[] | "- \(cell)"),
       ""
     else empty end),
    (if ($plan.warnings // []) | length > 0 then
       "### Endpoints",
       "",
       ($plan.warnings[] | "- \(cell)"),
       ""
     else empty end),
    "Dry run: nothing was changed."
  ]
| .[]
