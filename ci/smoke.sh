#!/usr/bin/env bash
# Runs a rotate binary built without dev-dependencies or features (what a
# release ships) through a few commands, each under a watchdog.
#
# `cargo test` turns on every feature that dev-dependencies ask for, so a
# dependency feature the release build lacks goes unnoticed there. This
# script is the check that runs the binary as users get it.
#
# Usage: ci/smoke.sh path/to/rotate
set -euo pipefail

bin=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
limit=${SMOKE_TIMEOUT:-20}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

failures=0

# run NAME EXPECTED_EXIT STDIN ARGS...: runs the binary with a time limit and
# checks the exit code. Output is kept in $work/NAME.out and NAME.err.
run() {
  local name=$1 expected=$2 input=$3
  shift 3
  printf '%s' "$input" | "$bin" "$@" >"$name.out" 2>"$name.err" &
  local pid=$!
  # Detached from stdout/stderr so a leftover `sleep` cannot hold a pipe open.
  ( sleep "$limit"; kill -9 "$pid" 2>/dev/null ) >/dev/null 2>&1 &
  local watchdog=$!
  local code=0
  wait "$pid" || code=$?
  kill "$watchdog" 2>/dev/null || true
  wait "$watchdog" 2>/dev/null || true
  if [ "$code" -eq 137 ]; then
    echo "FAIL $name: no exit within ${limit}s (hung)"
    failures=$((failures + 1))
  elif [ "$code" -ne "$expected" ]; then
    echo "FAIL $name: exit $code, expected $expected"
    sed 's/^/  stderr: /' "$name.err"
    failures=$((failures + 1))
  else
    echo "ok   $name"
  fi
}

run version 0 "" --version
run no-input 2 "" plan
run plan-stdin 0 "smoke-test-value-not-a-secret
" plan --stdin
run plan-json 0 "smoke-test-value-not-a-secret
" --json plan --stdin
run apply-no-input 2 "" apply
run status 0 "" status
run status-json 0 "" --json status --all

grep -q '^rotate ' version.out || { echo "FAIL version: unexpected output"; failures=$((failures + 1)); }
grep -q 'no input' no-input.err || { echo "FAIL no-input: message missing"; failures=$((failures + 1)); }
grep -q 'no input' apply-no-input.err || { echo "FAIL apply-no-input: message missing"; failures=$((failures + 1)); }
grep -qx 'no rotations' status.out || { echo "FAIL status: unexpected output"; failures=$((failures + 1)); }
grep -qx '\[\]' status-json.out || { echo "FAIL status-json: unexpected output"; failures=$((failures + 1)); }
grep -q 'unsupported' plan-stdin.out || { echo "FAIL plan-stdin: table missing"; failures=$((failures + 1)); }
grep -q 'smoke-test-value' plan-stdin.out plan-stdin.err plan-json.out plan-json.err \
  && { echo "FAIL: input value echoed"; failures=$((failures + 1)); }

if [ "$failures" -ne 0 ]; then
  echo "$failures smoke check(s) failed"
  exit 1
fi
echo "smoke checks passed"
