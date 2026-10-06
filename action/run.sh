#!/usr/bin/env bash
# The plan step of the rotate GitHub Action (SHA-198).
#
# Fetches secret-scanning alerts with the REST API and pipes the responses
# straight into `rotate plan --stdin --format github-alert`. The alert
# bodies go from curl's stdout to rotate's stdin through pipes only: never a
# file, a shell variable, jq or an environment variable. Everything written
# afterwards (plan.json, the summary, the outputs) comes from rotate's
# output, which never holds a secret value.
#
#   run.sh                 validate the inputs, fetch, plan, summarize
#   run.sh --check-inputs  validate the inputs only
#
# Environment (set by action.yml from the inputs):
#   ALERT_NUMBER        "", or alert numbers separated by commas
#   REPOSITORY          owner/repo
#   ALERTS_TOKEN        token with Secret scanning alerts: read
#   API_URL             GitHub REST API base URL
#   ROTATE_CONFIG_PATH  rotate.yaml path ("" for none)
#   MODE                plan
#   VERBOSE             0 to 3
#   ROTATE_BIN          the rotate binary (from install.sh)
# and by the runner: RUNNER_TEMP, GITHUB_OUTPUT, GITHUB_STEP_SUMMARY,
# GITHUB_SERVER_URL, GITHUB_REPOSITORY, GITHUB_RUN_ID.
#
# Exit codes: 2 for a bad input (before any request), 1 when the alerts
# could not be fetched (rotate is not run), otherwise rotate's own code.
#
# Never `set -x`: it would print the token. Works with bash 3.2.
set -euo pipefail

ACTION_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# The six secret types rotate can rotate, as GitHub names them. Poll mode
# lists the open alerts of these types.
SUPPORTED_TYPES=aws_secret_access_key,aws_access_key_id,github_personal_access_token,github_oauth_access_token,npm_access_token,openai_api_key

PERMISSION_HINT="the token needs Secret scanning alerts: read; GITHUB_TOKEN cannot read alerts"

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
    plan) ;;
    apply) bad_input "mode: apply is not available in this version of the Action (SHA-338); use plan" ;;
    *) bad_input "mode: must be plan" ;;
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
}

check_inputs
if [ "${1:-}" = --check-inputs ]; then
  exit 0
fi

# Everything this step writes is readable by the runner's user only.
umask 077
: "${RUNNER_TEMP:?RUNNER_TEMP is not set}"
: "${ROTATE_BIN:?ROTATE_BIN is not set; run install.sh first}"
API_URL=${API_URL%/}
SERVER_URL=${GITHUB_SERVER_URL:-https://github.com}
SUMMARY_FILE=${GITHUB_STEP_SUMMARY:-/dev/null}

work="$RUNNER_TEMP/rotate"
state_dir="$work/state"
plan_path="$work/plan.json"
summary_path="$work/summary.md"
status_file="$work/http-status"
log_file="$work/rotate.log"
mkdir -p "$work"
chmod 0700 "$work"
mkdir -p "$state_dir"
chmod 0700 "$state_dir"
rm -f "$plan_path" "$summary_path" "$status_file" "$log_file"

output() {
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"
  fi
}

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
  local verbosity=()
  case ${VERBOSE:-0} in
    1) verbosity=(-v) ;;
    2) verbosity=(-vv) ;;
    3) verbosity=(-vvv) ;;
  esac
  local config=()
  if [ -n "${ROTATE_CONFIG_PATH:-}" ] && [ -f "$ROTATE_CONFIG_PATH" ]; then
    config=(--config "$ROTATE_CONFIG_PATH")
  fi
  local rc=0
  { printf '%s' "$first"; cat; } |
    "$ROTATE_BIN" ${verbosity[@]+"${verbosity[@]}"} --json \
      --state-file "$state_dir/.rotate/state.json" \
      --audit-log "$state_dir/.rotate/audit.jsonl" \
      ${config[@]+"${config[@]}"} \
      plan --stdin --format github-alert > "$plan_path" 2> "$log_file" || rc=$?
  # rotate may stop reading early (a config error is reported before the
  # input is read). Drain the rest of the stream, unread, so curl never
  # fails on a closed pipe.
  cat > /dev/null
  return "$rc"
}

set +e
fetch_alerts | plan_alerts
statuses=("${PIPESTATUS[@]}")
set -e
fetch_status=${statuses[0]}
rotate_status=${statuses[1]}

output state-dir "$state_dir"

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

# rotate's stderr is redacted; show it in the log, then keep only the
# warning and error lines for the summary.
if [ -f "$log_file" ]; then
  cat "$log_file" >&2
fi
notes=$(grep -E '^(warning|error): ' "$log_file" 2>/dev/null || true)
rm -f "$log_file"

mode_name=list
if [ -n "${ALERT_NUMBER:-}" ]; then
  mode_name=numbers
fi
run_url=
if [ -n "${GITHUB_RUN_ID:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ]; then
  run_url="$SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
fi

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
