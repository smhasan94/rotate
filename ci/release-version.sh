#!/usr/bin/env bash
# Release version check (SHA-215 AC4).
#
#   ci/release-version.sh          prints version=<Cargo.toml version>
#   ci/release-version.sh v1.2.3   same, but exits 1 unless the tag is
#                                  exactly v<Cargo.toml version>
#
# The output line is meant for $GITHUB_OUTPUT. Run from the repository root.
set -euo pipefail

# `version` inside the [package] table, ignoring any other table.
version=$(awk '
  /^\[/ { in_package = ($0 == "[package]"); next }
  in_package && /^version[[:space:]]*=/ {
    sub(/^version[[:space:]]*=[[:space:]]*"/, "")
    sub(/".*$/, "")
    print
    exit
  }
' Cargo.toml)

if [ -z "$version" ]; then
  echo "release-version: no version in [package] of Cargo.toml" >&2
  exit 1
fi

if [ $# -gt 0 ]; then
  tag=$1
  if [ "$tag" != "v$version" ]; then
    echo "release-version: tag $tag does not match Cargo.toml version $version (expected v$version)" >&2
    exit 1
  fi
fi

echo "version=$version"
