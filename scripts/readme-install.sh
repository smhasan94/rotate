#!/usr/bin/env bash
# Runs the README install block exactly as written (SHA-271 T4).
#
#   scripts/readme-install.sh [README.md]
#
# Extracts the shell block between `<!-- install:start -->` and
# `<!-- install:end -->` and runs it with bash -eu in a fresh temporary
# directory. With --print, prints the block instead.
set -euo pipefail

print=false
if [ "${1:-}" = "--print" ]; then
  print=true
  shift
fi
readme=$(cd "$(dirname "${1:-README.md}")" && pwd)/$(basename "${1:-README.md}")

block=$(awk '
  /<!-- install:start -->/ { on = 1; next }
  /<!-- install:end -->/ { on = 0 }
  on && /^```/ { next }
  on { print }
' "$readme")

if [ -z "$block" ]; then
  echo "readme-install: no install block in $readme" >&2
  exit 1
fi
if $print; then
  printf '%s\n' "$block"
  exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
printf '%s\n' "$block" > install.sh
HOME="$work" bash -eu install.sh
