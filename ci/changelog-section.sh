#!/usr/bin/env bash
# Release notes from CHANGELOG.md (SHA-271).
#
#   ci/changelog-section.sh 0.1.0    prints the body of the `## [0.1.0]`
#                                    section, without its heading
#
# Exits 1 when CHANGELOG.md has no such section or it is empty. Run from
# the repository root.
set -euo pipefail

version=${1:?usage: ci/changelog-section.sh <version>}

body=$(awk -v heading="## [$version]" '
  index($0, heading) == 1 { found = 1; next }
  found && /^## \[/ { exit }
  found && /^\[[^]]+\]: / { exit }
  found { print }
' CHANGELOG.md)

# Trim blank lines at both ends.
body=$(printf '%s\n' "$body" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}')

if [ -z "$body" ]; then
  echo "changelog-section: no section for $version in CHANGELOG.md" >&2
  exit 1
fi
printf '%s\n' "$body"
