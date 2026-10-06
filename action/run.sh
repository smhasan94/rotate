#!/usr/bin/env bash
# The rotate step of the rotate GitHub Action: plan (SHA-198), or apply
# behind an environment approval (SHA-338).
#
# Fetches secret-scanning alerts with the REST API and pipes the responses
# straight into `rotate plan --stdin --format github-alert`, or with
# MODE=apply into `rotate apply --stdin --format github-alert --confirm ...
# --wait`. The alert bodies go from curl's stdout to rotate's stdin through
# pipes only: never a file, a shell variable, jq or an environment
# variable. Everything written afterwards (plan.json, status.json, the
# summary, the outputs) comes from rotate's output, which never holds a
# secret value.
#
#   run.sh                 validate the inputs, fetch, plan or apply, summarize
#   run.sh --check-inputs  validate the inputs only
#
# Environment (set by action.yml from the inputs):
#   ALERT_NUMBER        "", or alert numbers separated by commas
#   REPOSITORY          owner/repo
#   ALERTS_TOKEN        token with Secret scanning alerts: read
#   API_URL             GitHub REST API base URL
#   ROTATE_CONFIG_PATH  rotate.yaml path ("" for none)
#   MODE                plan or apply
#   VERBOSE             0 to 3
#   OVERLAP             "", or an overlap window such as 30m (--overlap)
#   UPLOAD_AUDIT        true or false (action.yml uploads the audit log)
#   CONFIRM             apply: rotation ids from the plan, comma-separated
#   FORCE               apply: true or false (--force)
#   REPLACEMENT_ENV     apply: "", or the name of the variable that holds
#                       a pasted replacement (--replacement-from-env)
#   PLAN_STATE_DIR      apply: where the plan job's state artifact is
#   MAX_WAIT            apply: the longest overlap window to wait out
#   ROTATE_BIN          the rotate binary (from install.sh)
# and by the runner: RUNNER_TEMP, GITHUB_OUTPUT, GITHUB_STEP_SUMMARY,
# GITHUB_SERVER_URL, GITHUB_REPOSITORY, GITHUB_RUN_ID.
#
# Exit codes: 2 for a bad input (before any request), 1 when the alerts
# could not be fetched (rotate is not run), otherwise rotate's own code.
# For apply that is 0 done, 1 failed (the old secret is still valid), 2
# nothing changed, 3 the overlap window ends after MAX_WAIT (the old
# secret is not revoked), 4 revoke by hand. When rotate exits 0 but a
# confirmed rotation is not at `revoked` (it found nothing to apply), the
# step exits 2.
#
# Never `set -x`: it would print the token. Works with bash 3.2.
set -euo pipefail

ACTION_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# The six secret types rotate can rotate, as GitHub names them. Poll mode
# lists the open alerts of these types.
SUPPORTED_TYPES=aws_secret_access_key,aws_access_key_id,github_personal_access_token,github_oauth_access_token,npm_access_token,openai_api_key

PERMISSION_HINT="the token needs Secret scanning alerts: read; GITHUB_TOKEN cannot read alerts"

# rotate's duration grammar (`overlap_window`), at most 9 digits a group.
DURATION='^([0-9]{1,9}[dhms])+$'

# A workflow command's message, escaped so it stays one command:
# `%`, CR and LF are encoded as GitHub documents.
annotate() {
  local message=$1
  message=${message//%/%25}
  message=${message//$'\r'/%0D}
  message=${message//$'\n'/%0A}
  printf '::error title=rotate::%s\n' "$message" >&2
}

# One line naming the input, exit 2 (AC6). Never echoes the raw input.
bad_input() {
  annotate "input $1"
  exit 2
}

check_inputs() {
  case ${MODE:-plan} in
    plan | apply) ;;
    *) bad_input "mode: must be plan or apply" ;;
  esac
  if [ -n "${ALERT_NUMBER:-}" ] && ! [[ $ALERT_NUMBER =~ ^[0-9]+(,[0-9]+)*$ ]]; then
    bad_input "alert-number: must be digits separated by commas, such as 42 or 42,43"
  fi
  local owner repo
  owner=${REPOSITORY%%/*}
  repo=${REPOSITORY#*/}
  if ! [[ ${REPOSITORY:-} =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] ||
    [ "$owner" = . ] || [ "$owner" = .. ] || [ "$repo" = . ] || [ "$repo" = .. ]; then
    bad_input "repository: must be owner/repo"
  fi
  if [ -z "${ALERTS_TOKEN:-}" ]; then
    bad_input "alerts-token: is empty; pass a token with Secret scanning alerts: read"
  fi
  # The token goes into a curl config line, so it must not hold quotes,
  # backslashes, spaces or control characters. GitHub tokens never do.
  if ! [[ $ALERTS_TOKEN =~ ^[A-Za-z0-9_.~+/=-]+$ ]]; then
    bad_input "alerts-token: is not a GitHub token"
  fi
  # The token must not travel in clear text, except to this machine.
  if ! [[ ${API_URL:-} =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[^?#[:space:]]*)?$ ]] &&
    ! [[ ${API_URL:-} =~ ^http://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)?(/[^?#[:space:]]*)?$ ]]; then
    bad_input "api-url: must be an https URL, or http to a loopback address"
  fi
  case ${VERBOSE:-0} in
    0 | 1 | 2 | 3) ;;
    *) bad_input "verbose: must be 0, 1, 2 or 3" ;;
  esac
  if [[ ${ROTATE_CONFIG_PATH:-} =~ [[:cntrl:]] ]]; then
    bad_input "config: must not contain control characters"
  fi
  if [ -n "${ROTATE_CONFIG_PATH:-}" ] && [ "$ROTATE_CONFIG_PATH" != rotate.yaml ] &&
    [ ! -f "$ROTATE_CONFIG_PATH" ]; then
    bad_input "config: the file does not exist"
  fi
  if [ -n "${OVERLAP:-}" ] && ! [[ $OVERLAP =~ $DURATION ]]; then
    bad_input "overlap: must be a duration such as 30m or 1h30m"
  fi
  case ${UPLOAD_AUDIT:-true} in
    true | false) ;;
    *) bad_input "upload-audit: must be true or false" ;;
  esac
  case ${FORCE:-false} in
    true | false) ;;
    *) bad_input "force: must be true or false" ;;
  esac
  if [ -n "${CONFIRM:-}" ] && ! [[ $CONFIRM =~ ^rot-[0-9a-f]{8}(,rot-[0-9a-f]{8})*$ ]]; then
    bad_input "confirm: must be rotation ids from the plan separated by commas, such as rot-1a2b3c4d,rot-5e6f7a8b"
  fi
  if [ -n "${REPLACEMENT_ENV:-}" ] && ! [[ $REPLACEMENT_ENV =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    bad_input "replacement-env: must be the name of an environment variable, such as NEW_TOKEN"
  fi
  if ! [[ ${MAX_WAIT:-5h} =~ $DURATION ]]; then
    bad_input "max-wait: must be a duration such as 30m or 1h30m"
  fi
  if [[ ${PLAN_STATE_DIR:-} =~ [[:cntrl:]] ]]; then
    bad_input "state-dir: must not contain control characters"
  fi
  if [ "${MODE:-plan}" = plan ]; then
    # What only apply reads is refused in plan mode, not ignored.
    [ -z "${CONFIRM:-}" ] || bad_input "confirm: only with mode: apply"
    [ -z "${PLAN_STATE_DIR:-}" ] || bad_input "state-dir: only with mode: apply"
    [ -z "${REPLACEMENT_ENV:-}" ] || bad_input "replacement-env: only with mode: apply"
    [ "${FORCE:-false}" = false ] || bad_input "force: only with mode: apply"
    return 0
  fi
  [ -n "${CONFIRM:-}" ] ||
    bad_input "confirm: is empty; pass the plan job's rotation-ids output"
  # The plan job's state file holds the rotation ids --confirm names.
  [ -n "${PLAN_STATE_DIR:-}" ] ||
    bad_input "state-dir: is empty; pass the directory the plan job's state artifact was downloaded to"
  local dir="$PLAN_STATE_DIR/.rotate"
  if [ ! -d "$PLAN_STATE_DIR" ] || [ -L "$dir" ] || [ ! -d "$dir" ] ||
    [ -L "$dir/state.json" ] || [ ! -f "$dir/state.json" ]; then
    bad_input "state-dir: has no .rotate/state.json; download the plan job's state artifact there"
  fi
  if [ -L "$dir/audit.jsonl" ] || { [ -e "$dir/audit.jsonl" ] && [ ! -f "$dir/audit.jsonl" ]; }; then
    bad_input "state-dir: .rotate/audit.jsonl is not a regular file"
  fi
}

check_inputs
if [ "${1:-}" = --check-inputs ]; then
  exit 0
fi

# Everything this step writes is readable by the runner's user only.
umask 077
: "${RUNNER_TEMP:?RUNNER_TEMP is not set}"
: "${ROTATE_BIN:?ROTATE_BIN is not set; run install.sh first}"
MODE=${MODE:-plan}
MAX_WAIT=${MAX_WAIT:-5h}
API_URL=${API_URL%/}
SERVER_URL=${GITHUB_SERVER_URL:-https://github.com}
SUMMARY_FILE=${GITHUB_STEP_SUMMARY:-/dev/null}

work="$RUNNER_TEMP/rotate"
state_dir="$work/state"
plan_path="$work/plan.json"
status_path="$work/status.json"
summary_path="$work/summary.md"
status_file="$work/http-status"
log_file="$work/rotate.log"
probe_dir="$work/probe"
mkdir -p "$work"
chmod 0700 "$work"
mkdir -p "$state_dir"
chmod 0700 "$state_dir"
rm -rf "$probe_dir"
rm -f "$plan_path" "$status_path" "$summary_path" "$status_file" "$log_file"

output() {
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"
  fi
}

# Set before any fetch, probe or apply: the audit upload in action.yml
# runs on always() and needs it even when this step is killed or times
# out in the middle of a --wait.
output state-dir "$state_dir"

# The summary goes to the job summary and to the log.
publish_summary() {
  cat "$summary_path" >> "$SUMMARY_FILE"
  cat "$summary_path"
  output summary-path "$summary_path"
}

# Redirects stay on https; plain http only for the loopback test server.
case $API_URL in
  https://*) protocols=(--proto '=https' --proto-redir '=https') ;;
  *) protocols=(--proto '=https,http' --proto-redir '=https,http') ;;
esac

alerts_url="$API_URL/repos/$REPOSITORY/secret-scanning/alerts"
urls=()
if [ -n "${ALERT_NUMBER:-}" ]; then
  # Digits and commas only (checked above), so splitting is safe.
  for n in ${ALERT_NUMBER//,/ }; do
    urls+=("$alerts_url/$n")
  done
  # The open access key id alerts, so an aws_secret_access_key alert can be
  # paired with its key id (docs/report-formats.md).
  urls+=("$alerts_url?state=open&secret_type=aws_access_key_id&per_page=100")
else
  # Poll mode: one request, first 100 open alerts, no pagination.
  urls+=("$alerts_url?state=open&per_page=100&secret_type=$SUPPORTED_TYPES")
fi

# The configuration flags every rotate run of this step shares, and the
# full set with the verbosity and this run's state directory.
config_flags=()
if [ -n "${ROTATE_CONFIG_PATH:-}" ] && [ -f "$ROTATE_CONFIG_PATH" ]; then
  config_flags+=(--config "$ROTATE_CONFIG_PATH")
fi
if [ -n "${OVERLAP:-}" ]; then
  config_flags+=(--overlap "$OVERLAP")
fi
rotate_flags=()
case ${VERBOSE:-0} in
  1) rotate_flags+=(-v) ;;
  2) rotate_flags+=(-vv) ;;
  3) rotate_flags+=(-vvv) ;;
esac
rotate_flags+=(
  --state-file "$state_dir/.rotate/state.json"
  --audit-log "$state_dir/.rotate/audit.jsonl"
  ${config_flags[@]+"${config_flags[@]}"}
)

# GETs every URL in turn, bodies to stdout. The token reaches curl as a
# config line on its stdin (printf is a shell builtin), so it never appears
# in a process's arguments. Each request's HTTP status goes to
# $status_file, and curl's exit code as `curl-exit=N` when it fails.
#
# A failed request is an API failure, except curl exit 23 (it could not
# write its output): that means rotate stopped reading, for example on a
# bad rotate.yaml, and rotate's exit code tells what happened. On an API
# failure nothing more is fetched and a byte that is not JSON is written,
# so rotate refuses the whole input instead of planning part of it.
fetch_alerts() {
  local url rc
  for url in "${urls[@]}"; do
    rc=0
    printf 'header = "Authorization: Bearer %s"\n' "$ALERTS_TOKEN" |
      curl --disable --config - --silent --show-error --fail --location --max-redirs 3 \
        "${protocols[@]}" --connect-timeout 20 --max-time 120 \
        --user-agent rotate-action \
        --header 'Accept: application/vnd.github+json' \
        --header 'X-GitHub-Api-Version: 2022-11-28' \
        --write-out '%{stderr}%{http_code}\n' \
        "$url" 2>> "$status_file" || rc=$?
    if [ "$rc" -eq 23 ]; then
      return 0
    elif [ "$rc" -ne 0 ]; then
      printf 'curl-exit=%s\n' "$rc" >> "$status_file"
      printf '\n!\n'
      return 1
    fi
  done
}

# Runs rotate on the fetched stream, unless the stream is empty, which
# means the first request failed: then rotate is not started at all. Only
# the first byte, `{` or `[` from GitHub, is read here; the rest goes to
# rotate through the pipe unread.
plan_alerts() {
  # This function runs in its own subshell (a pipeline stage): rotate does
  # not need the alerts token, so it does not inherit it.
  unset ALERTS_TOKEN
  local first=
  IFS= read -r -n 1 first || true
  if [ -z "$first" ]; then
    return 99
  fi
  local rc=0
  { printf '%s' "$first"; cat; } |
    "$ROTATE_BIN" "${rotate_flags[@]}" --json \
      plan --stdin --format github-alert > "$plan_path" 2> "$log_file" || rc=$?
  # rotate may stop reading early (a config error is reported before the
  # input is read). Drain the rest of the stream, unread, so curl never
  # fails on a closed pipe.
  cat > /dev/null
  return "$rc"
}

# As plan_alerts, for `rotate apply`: confirmed by id, so no prompt is
# asked. rotate's stdout (the plan and the apply summary) goes to the log
# as it comes, and so does its stderr, which is also kept in $log_file for
# the job summary: a --wait run can last the whole overlap window.
apply_alerts() {
  unset ALERTS_TOKEN
  exec 3>&1
  local first=
  IFS= read -r -n 1 first || true
  if [ -z "$first" ]; then
    return 99
  fi
  local args=(apply --stdin --format github-alert) id
  # rot- ids separated by commas only (checked above).
  for id in ${CONFIRM//,/ }; do
    args+=(--confirm "$id")
  done
  if [ "${FORCE:-false}" = true ]; then
    args+=(--force)
  fi
  if [ -n "${REPLACEMENT_ENV:-}" ]; then
    args+=(--replacement-from-env "$REPLACEMENT_ENV")
  fi
  args+=(${wait_flag[@]+"${wait_flag[@]}"})
  local statuses
  set +e
  { printf '%s' "$first"; cat; } |
    "$ROTATE_BIN" "${rotate_flags[@]}" "${args[@]}" 2>&1 >&3 3>&- |
    tee "$log_file" >&2
  statuses=("${PIPESTATUS[@]}")
  set -e
  cat > /dev/null
  return "${statuses[1]}"
}

# What both summaries show. $notes holds rotate's warning, error and note
# lines, taken from its redacted stderr.
notes=
run_url=
if [ -n "${GITHUB_RUN_ID:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ]; then
  run_url="$SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
fi
mode_name=list
if [ -n "${ALERT_NUMBER:-}" ]; then
  mode_name=numbers
fi

# Renders the apply summary from status.json (if any) and $notes, then
# publishes it.
apply_summary() {
  local code=$1 overlap=$2 not_applied=$3 rows_arg=()
  if [ -s "$status_path" ]; then
    rows_arg=(--slurpfile rows "$status_path")
  else
    rows_arg=(--argjson rows '[]')
  fi
  jq -n -r \
    "${rows_arg[@]}" \
    --arg repository "$REPOSITORY" \
    --arg alerts "${ALERT_NUMBER:-}" \
    --arg mode "$mode_name" \
    --arg server "$SERVER_URL" \
    --arg run_url "$run_url" \
    --arg notes "$notes" \
    --arg exit_code "$code" \
    --arg confirm "$CONFIRM" \
    --arg overlap "$overlap" \
    --arg max_wait "$MAX_WAIT" \
    --arg not_applied "$not_applied" \
    -f "$ACTION_DIR/apply-summary.jq" > "$summary_path"
  publish_summary
}

# A duration in rotate's grammar, in seconds; a group of more than 9
# digits counts as longer than any wait.
duration_seconds() {
  local rest=$1 total=0 n unit
  [ -n "$rest" ] || return 1
  while [[ $rest =~ ^([0-9]+)([dhms])(.*)$ ]]; do
    n=${BASH_REMATCH[1]}
    unit=${BASH_REMATCH[2]}
    rest=${BASH_REMATCH[3]}
    if [ ${#n} -gt 9 ]; then
      echo 999999999999999
      return 0
    fi
    n=$((10#$n))
    case $unit in
      d) n=$((n * 86400)) ;;
      h) n=$((n * 3600)) ;;
      m) n=$((n * 60)) ;;
    esac
    total=$((total + n))
  done
  [ -z "$rest" ] || return 1
  echo "$total"
}

wait_flag=()
overlap=
if [ "$MODE" = apply ]; then
  # The plan job's state, copied into this runner's private state
  # directory: rotate refuses a state file that others can read, and an
  # artifact download does not keep the 0600 mode. Only the two files
  # rotate keeps there are copied, and never through a symbolic link.
  mkdir -p "$state_dir/.rotate"
  chmod 0700 "$state_dir/.rotate"
  from=$(cd "$PLAN_STATE_DIR/.rotate" && pwd -P)
  to=$(cd "$state_dir/.rotate" && pwd -P)
  if [ "$from" != "$to" ]; then
    for name in state.json audit.jsonl; do
      rm -f "$to/$name"
      if [ -f "$from/$name" ] && [ ! -L "$from/$name" ]; then
        cp "$from/$name" "$to/$name"
        chmod 0600 "$to/$name"
      fi
    done
  fi

  # The overlap window apply will use, as rotate resolves it from
  # --overlap, ROTATE_OVERLAP and rotate.yaml: a plan of no alerts prints
  # it, makes no call, and writes only to its own scratch directory. A
  # configuration error stops the step here, before any request.
  mkdir -p "$probe_dir"
  probe_status=0
  (
    unset ALERTS_TOKEN
    printf '[]' |
      "$ROTATE_BIN" --json ${config_flags[@]+"${config_flags[@]}"} \
        --state-file "$probe_dir/state.json" --audit-log "$probe_dir/audit.jsonl" \
        plan --stdin --format github-alert > "$probe_dir/plan.json" 2> "$log_file"
  ) || probe_status=$?
  if [ "$probe_status" -eq 0 ]; then
    overlap=$(jq -r '.overlap_window // empty' "$probe_dir/plan.json" 2>/dev/null || true)
  fi
  rm -rf "$probe_dir"
  if [ "$probe_status" -ne 0 ]; then
    cat "$log_file" >&2
    notes=$(grep -E '^(warning|error|note): ' "$log_file" 2>/dev/null || true)
    rm -f "$log_file"
    annotate "rotate apply did not start (exit $probe_status); nothing was changed. See the job summary."
    apply_summary "$probe_status" "" ""
    output exit-code "$probe_status"
    exit "$probe_status"
  fi
  rm -f "$log_file"

  # A runner cannot come back later, so apply waits out the overlap window
  # (--wait), unless the window is longer than the job may run (MAX_WAIT):
  # then apply stops before the revoke and exits 3 with the revoke time.
  overlap_secs=$(duration_seconds "$overlap" || echo 999999999999999)
  max_secs=$(duration_seconds "$MAX_WAIT")
  if [ "$overlap_secs" -le "$max_secs" ]; then
    wait_flag=(--wait)
  else
    printf 'The overlap window (%s) is longer than max-wait (%s): rotate will not wait, and the old secret will not be revoked in this run.\n' \
      "${overlap:-unknown}" "$MAX_WAIT" >&2
  fi

  # A revoke time an earlier apply recorded for a confirmed rotation wins
  # over this run's window (rotate keeps it), so wait only if that time too
  # is within max-wait. `rotate status` reads the state file only; it exits
  # 3 while a rotation is pending. When the time cannot be read, no wait.
  if [ ${#wait_flag[@]} -gt 0 ]; then
    pending_secs=unknown
    status_rc=0
    (
      unset ALERTS_TOKEN
      "$ROTATE_BIN" "${rotate_flags[@]}" --json status --all > "$status_path"
    ) || status_rc=$?
    if [ "$status_rc" -eq 0 ] || [ "$status_rc" -eq 3 ]; then
      pending_secs=$(jq -r --arg ids "$CONFIRM" \
        '[.[] | select(.rotation_id as $id | $ids | split(",") | index($id)) | .revoke_remaining_seconds // empty] | max // 0' \
        "$status_path" 2>/dev/null || echo unknown)
    fi
    rm -f "$status_path"
    if ! [[ $pending_secs =~ ^[0-9]+$ ]] || [ "$pending_secs" -gt "$max_secs" ]; then
      wait_flag=()
      printf 'A confirmed rotation has a revoke time recorded more than max-wait (%s) from now, or it could not be read: rotate will not wait, and the old secret will not be revoked in this run.\n' \
        "$MAX_WAIT" >&2
    fi
  fi
fi

set +e
if [ "$MODE" = apply ]; then
  fetch_alerts | apply_alerts
else
  fetch_alerts | plan_alerts
fi
statuses=("${PIPESTATUS[@]}")
set -e
fetch_status=${statuses[0]}
rotate_status=${statuses[1]}

# AC7: the alerts could not be fetched. The summary holds this message only.
if [ "$fetch_status" -ne 0 ] || [ "$rotate_status" -eq 99 ]; then
  http=$(grep -E '^[0-9]{3}$' "$status_file" 2>/dev/null | tail -n 1 || true)
  if [ "$fetch_status" -eq 0 ]; then
    message="The secret-scanning alerts API at $API_URL returned an empty response."
  else
    case $http in
      401 | 403 | 404)
        message="The secret-scanning alerts API answered HTTP $http for $REPOSITORY: $PERMISSION_HINT. A 404 can also mean the alert does not exist or secret scanning is off."
        ;;
      000 | '')
        # curl's own error line, such as "Could not resolve host".
        reason=$(grep -E '^curl: ' "$status_file" 2>/dev/null | tail -n 1 || true)
        message="Could not reach the secret-scanning alerts API at $API_URL${reason:+ ($reason)}."
        ;;
      *)
        message="The secret-scanning alerts API answered HTTP $http for $REPOSITORY."
        ;;
    esac
  fi
  annotate "$message"
  printf '%s\n' "$message" > "$summary_path"
  rm -f "$plan_path" "$log_file" "$status_file"
  publish_summary
  output exit-code 1
  exit 1
fi
rm -f "$status_file"

if [ "$MODE" = apply ]; then
  # apply's stderr was shown as it came; keep the notes for the summary.
  notes=$(grep -E '^(warning|error|note): ' "$log_file" 2>/dev/null || true)
  rm -f "$log_file"
  # `rotate status` reads the state file and audit log only; it exits 3
  # while any rotation is pending, which is not an error here.
  status_rc=0
  (
    unset ALERTS_TOKEN
    "$ROTATE_BIN" "${rotate_flags[@]}" --json status --all > "$status_path"
  ) || status_rc=$?
  if [ "$status_rc" -ne 0 ] && [ "$status_rc" -ne 3 ]; then
    rm -f "$status_path"
  fi
  # rotate exits 0 with "Nothing to apply." when the alerts fetched again
  # plan nothing, for example when an alert was resolved or a secret
  # revoked while the job waited for approval. Done means every confirmed
  # rotation is revoked; anything else is reported as not applied, exit 2.
  not_applied=
  if [ "$rotate_status" -eq 0 ]; then
    if [ -s "$status_path" ]; then
      not_applied=$(jq -r --arg ids "$CONFIRM" \
        '[.[] | select(.step == "revoked") | .rotation_id] as $done
         | [$ids | split(",")[] | select(. as $id | $done | index($id) | not)]
         | join(",")' "$status_path" 2>/dev/null) || not_applied=$CONFIRM
    else
      not_applied=$CONFIRM
    fi
    if [ -n "$not_applied" ]; then
      rotate_status=2
    fi
  fi
  case $rotate_status in
    0) ;;
    2)
      if [ -n "$not_applied" ]; then
        annotate "The confirmed rotations $not_applied were not applied: rotate apply found nothing to do for them. See the job summary."
      else
        annotate "rotate apply exited with code 2; nothing was changed. See the job summary."
      fi
      ;;
    1) annotate "rotate apply failed; the old secret is still valid. See the job summary." ;;
    3)
      at=$(jq -r --arg ids "$CONFIRM" \
        '[.[] | select(.rotation_id as $id | $ids | split(",") | index($id)) | .revoke_not_before // empty] | max // empty' \
        "$status_path" 2>/dev/null || true)
      annotate "The overlap window ends at ${at:-an unknown time}, after max-wait ($MAX_WAIT): the old secret was not revoked. See the job summary."
      ;;
    4) annotate "rotate cannot revoke the old secret: revoke it by hand as the job summary says." ;;
    *) annotate "rotate apply exited with code $rotate_status. See the job summary." ;;
  esac
  apply_summary "$rotate_status" "$overlap" "$not_applied"
  output exit-code "$rotate_status"
  exit "$rotate_status"
fi

# rotate's stderr is redacted; show it in the log, then keep only the
# warning and error lines for the summary.
if [ -f "$log_file" ]; then
  cat "$log_file" >&2
fi
notes=$(grep -E '^(warning|error): ' "$log_file" 2>/dev/null || true)
rm -f "$log_file"

plan_arg=()
if [ "$rotate_status" -eq 0 ] && [ -s "$plan_path" ]; then
  plan_arg=(--slurpfile plans "$plan_path")
else
  plan_arg=(--argjson plans '[]')
fi
jq -n -r \
  ${plan_arg[@]+"${plan_arg[@]}"} \
  --arg repository "$REPOSITORY" \
  --arg alerts "${ALERT_NUMBER:-}" \
  --arg mode "$mode_name" \
  --arg server "$SERVER_URL" \
  --arg run_url "$run_url" \
  --arg notes "$notes" \
  --arg exit_code "$rotate_status" \
  -f "$ACTION_DIR/summary.jq" > "$summary_path"
publish_summary

ids=
if [ "$rotate_status" -eq 0 ] && [ -s "$plan_path" ]; then
  ids=$(jq -r '[.rotations[].rotation_id] | join(",")' "$plan_path")
  output plan-path "$plan_path"
fi
output rotation-ids "$ids"
output exit-code "$rotate_status"
exit "$rotate_status"
