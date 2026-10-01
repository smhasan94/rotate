#!/usr/bin/env bash
# Docs checks for SHA-213.
#   T1: README.md names the safety guarantees, SECURITY.md says how to report.
#   T2: the four check commands in CONTRIBUTING.md match CLAUDE.md exactly.
# Run from the repository root. Exits non-zero on any miss.
set -euo pipefail

fail=0

require() {
  local file=$1 phrase=$2
  if ! grep -qiF -- "$phrase" "$file"; then
    echo "check-docs: $file does not mention \"$phrase\""
    fail=1
  fi
}

# T1
require README.md "dry run"
require README.md "zeroized"
require README.md "revoke"
require SECURITY.md "report"

# T2: first ```sh block after the given heading.
sh_block() {
  local file=$1 heading=$2
  awk -v h="$heading" '
    $0 == h { in_section = 1; next }
    in_section && /^## / { exit }
    in_section && /^```sh$/ { in_block = 1; next }
    in_block && /^```$/ { exit }
    in_block { print }
  ' "$file"
}

claude=$(sh_block CLAUDE.md "## Commands")
contributing=$(sh_block CONTRIBUTING.md "## Checks")

if [ "$(grep -c '^cargo ' <<<"$claude")" -ne 4 ]; then
  echo "check-docs: expected four cargo commands under '## Commands' in CLAUDE.md, found:"
  echo "$claude"
  fail=1
fi

if [ "$claude" != "$contributing" ]; then
  echo "check-docs: the commands under '## Checks' in CONTRIBUTING.md differ from CLAUDE.md:"
  diff <(echo "$claude") <(echo "$contributing") || true
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "check-docs: ok"
