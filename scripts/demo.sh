#!/usr/bin/env bash
# The README demo (SHA-340): the MVP success scenario, simulated.
#
#   scripts/demo.sh
#
# A TruffleHog report holds a leaked AWS access key that one GitHub Actions
# secret and one Secrets Manager entry use. The script runs `rotate plan`,
# `rotate apply` with the typed confirmation, `rotate status --all`, and
# shows the audit log.
#
# Nothing here is real. rotate runs as a `test-providers` build: a mock AWS
# provider and mock GitHub Actions and Secrets Manager consumers, chosen by
# a scenario file (ROTATE_TEST_SCENARIO), stand in for the real plugins.
# They make no network call and need no credentials. The leaked key is fake
# and made up at run time. Never point this script at a real report.
#
# Environment (all optional):
#   ROTATE_BIN   a rotate binary built with `--features test-providers`.
#                Default: `cargo build --features test-providers`, then
#                target/debug/rotate.
#   DEMO_DIR     a directory to run in, kept afterwards (tests sweep it).
#                Default: a temporary directory, removed on exit.
#   DEMO_KEY_ID, DEMO_SECRET
#                the fake leaked key pair. Default: random, made here.
#   DEMO_PACE    seconds to pause after each command, for a recording.
#                Default: 0.
#   NO_COLOR     set to print the command lines without bold and dim.
#
# Layout under the run directory: `work/` is where rotate runs (the report,
# rotate.yaml, .rotate/); `mock/` holds the scenario and what the mocks
# record, one call log per command (plan.jsonl, apply.jsonl, status.jsonl),
# by fingerprint only.
#
# Exit status: 0 when plan, apply and status all exit 0; otherwise the
# first non-zero status.
#
# The typed confirmation: apply asks for the rotation id on the terminal.
# Here the scenario's scripted prompt answers it with the id plan assigned
# (the test build's stand-in for the keyboard), and the script echoes that
# answer after the question so the recording shows what was typed.
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
pace=${DEMO_PACE:-0}

if [ -z "${ROTATE_BIN:-}" ]; then
  cargo build --quiet --manifest-path "$repo/Cargo.toml" --features test-providers
  ROTATE_BIN="$repo/target/debug/rotate"
fi
if [ ! -x "$ROTATE_BIN" ]; then
  echo "demo: no rotate binary at $ROTATE_BIN" >&2
  exit 1
fi

if [ -n "${DEMO_DIR:-}" ]; then
  mkdir -p "$DEMO_DIR"
  root=$(cd "$DEMO_DIR" && pwd)
else
  root=$(mktemp -d)
  trap 'rm -rf "$root"' EXIT
fi
work="$root/work"
mock="$root/mock"
mkdir -p "$work" "$mock"

# `len` random characters from the tr set `chars`.
random() {
  LC_ALL=C tr -dc "$2" </dev/urandom | head -c "$1" || true
}

key_id=${DEMO_KEY_ID:-AKIA$(random 16 'A-Z2-7')}
secret=${DEMO_SECRET:-$(random 40 'A-Za-z0-9/+')}

# The fingerprint rotate shows: `sha256:` and the first 16 hex characters
# of the SHA-256 of the secret half (src/secret.rs). The mocks match
# consumers by it.
if command -v sha256sum >/dev/null 2>&1; then
  digest=$(printf '%s' "$secret" | sha256sum)
else
  digest=$(printf '%s' "$secret" | shasum -a 256)
fi
fingerprint="sha256:${digest:0:16}"

# The leaked key as TruffleHog reports it. The fixture's placeholders are
# filled here so no key is ever committed (tests/fixtures/README.md).
sed -e "s|@KEY_ID@|$key_id|g" -e "s|@SECRET@|$secret|g" \
  "$repo/tests/fixtures/demo/trufflehog.ndjson" >"$work/trufflehog.json"
unset secret digest DEMO_SECRET
cp "$repo/tests/fixtures/demo/rotate.yaml" "$work/rotate.yaml"

# The mocks for one command: the GitHub Actions secret
# acme/api AWS_SECRET_ACCESS_KEY holds the secret half (matched by name),
# the Secrets Manager entry prod/app holds the pair (matched by value).
# Fingerprints only. $1 names the call log, $2 is the prompt.
scenario() {
  local prompt=${2:-'"no_tty"'}
  cat >"$mock/scenario.json" <<EOF
{
  "consumers": [
    { "name": "github-actions", "matches": [
      { "fingerprint": "$fingerprint", "method": "by_name", "holds": "secret",
        "ref": "github-actions:acme/api:AWS_SECRET_ACCESS_KEY" } ] },
    { "name": "aws-secrets-manager", "matches": [
      { "fingerprint": "$fingerprint", "holds": "key_pair",
        "ref": "aws-secrets-manager:prod/app" } ] }
  ],
  "prompt": $prompt,
  "call_log": "$mock/$1.jsonl"
}
EOF
}

export ROTATE_TEST_SCENARIO="$mock/scenario.json"
export ROTATE_ACTOR="${ROTATE_ACTOR:-demo@example.com}"
unset ROTATE_CONFIG ROTATE_STATE_FILE ROTATE_AUDIT_LOG ROTATE_OVERLAP
cd "$work"

bold=$(printf '\033[1m')
dim=$(printf '\033[2m')
plain=$(printf '\033[0m')
if [ -n "${NO_COLOR:-}" ]; then
  bold='' dim='' plain=''
fi

say() {
  printf '%s# %s%s\n' "$dim" "$*" "$plain"
}

# Shows a command line; typed out one character at a time when pacing.
shown() {
  local line="$*" i
  printf '%s$ ' "$bold"
  if [ "$pace" = 0 ]; then
    printf '%s' "$line"
  else
    for ((i = 0; i < ${#line}; i++)); do
      printf '%s' "${line:i:1}"
      sleep 0.03
    done
  fi
  printf '%s\n' "$plain"
}

# When pacing, waits, then clears the screen for the next step.
pause() {
  if [ "$pace" != 0 ]; then
    sleep "$pace"
    if [ "${1:-}" != last ]; then
      printf '\033[H\033[2J'
    fi
  fi
}

# Exits with `status` unless it is 0.
check() {
  if [ "$2" -ne 0 ]; then
    echo "demo: rotate $1 exited $2" >&2
    exit "$2"
  fi
  echo
  pause
}

say "Simulated: a test build of rotate with mock AWS, GitHub Actions and"
say "Secrets Manager. No real credentials, no network, a fake key."
echo

scenario plan
shown rotate plan trufflehog.json
status=0
"$ROTATE_BIN" plan trufflehog.json || status=$?
check plan "$status"

# The id plan assigned; the state file keeps it for apply.
id=$(grep -o 'rot-[0-9a-f]\{8\}' .rotate/state.json | head -n 1 || true)
if [ -z "$id" ]; then
  echo "demo: plan recorded no rotation" >&2
  exit 1
fi

# apply prints the question on stderr with no newline and reads the answer;
# the merged output goes through sed to show the answer after it.
scenario apply "{ \"answers\": [\"$id\"] }"
shown rotate apply trufflehog.json
set +o errexit
"$ROTATE_BIN" apply trufflehog.json 2>&1 |
  sed -u "s/to continue: /to continue: $id\\
/"
status=${PIPESTATUS[0]}
set -o errexit
check apply "$status"

scenario status
shown rotate status --all
status=0
"$ROTATE_BIN" status --all || status=$?
check status "$status"

say "The audit log, .rotate/audit.jsonl: every step, the secret by"
say "fingerprint only (shown: step, outcome, fingerprint, consumer)."
sed -E \
  -e 's/.*"fingerprint":"([^"]*)".*"step":"([^"]*)","outcome":"([^"]*)".*/\2 \3 \1 &/' \
  -e 's/^([^ ]+ [^ ]+ [^ ]+) .*"consumer":"([^"]*)".*/\1 \2/' \
  -e 's/^([^ ]+ [^ ]+ [^ ]+) \{.*/\1/' \
  .rotate/audit.jsonl |
  awk '{ line = sprintf("  %-8s %-4s %s  %s", $1, $2, $3, $4); sub(/ +$/, "", line); print line }'
echo
pause last
