#!/usr/bin/env bash
# Verifies a published GitHub Release of rotate (SHA-271).
#
#   scripts/verify-release.sh v0.1.0
#
# 1. Downloads the four tarballs and SHA256SUMS, checks SHA256SUMS lists
#    exactly those four and that every checksum verifies (AC2).
# 2. Extracts the tarball for this host and checks `rotate --version`
#    prints `rotate <version>` (AC2).
# 3. Smoke check (AC3): `rotate plan` on tests/fixtures/trufflehog.ndjson
#    in an empty environment exits 0 with the dry-run line, skips every
#    finding as invalid or unknown (so every provider is registered), does
#    not panic and prints none of the fixture's secrets.
#
# ROTATE_REPO overrides the repository (default smhasan94/rotate).
set -euo pipefail

tag=${1:?usage: scripts/verify-release.sh vX.Y.Z}
version=${tag#v}
repo=${ROTATE_REPO:-smhasan94/rotate}
root=$(cd "$(dirname "$0")/.." && pwd)
fixture="$root/tests/fixtures/trufflehog.ndjson"
targets="x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin"

fail() {
  echo "verify-release: $*" >&2
  exit 1
}

sha256_check() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "$@"
  else
    shasum -a 256 -c "$@"
  fi
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

# 1. Every asset and its checksum.
base="https://github.com/$repo/releases/download/$tag"
for target in $targets; do
  curl -fsSLO "$base/rotate-$version-$target.tar.gz"
done
curl -fsSLO "$base/SHA256SUMS"
expected=$(for target in $targets; do echo "rotate-$version-$target.tar.gz"; done | sort)
listed=$(awk '{ sub(/^\*/, "", $2); print $2 }' SHA256SUMS | sort)
[ "$listed" = "$expected" ] || fail "SHA256SUMS does not list exactly the four tarballs: $listed"
sha256_check SHA256SUMS
echo "checksums: ok"

# 2. The host's binary.
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) host=x86_64-unknown-linux-gnu ;;
  Linux-aarch64 | Linux-arm64) host=aarch64-unknown-linux-gnu ;;
  Darwin-x86_64) host=x86_64-apple-darwin ;;
  Darwin-arm64) host=aarch64-apple-darwin ;;
  *) fail "no release binary for $(uname -sm)" ;;
esac
mkdir bin
tar -xzf "rotate-$version-$host.tar.gz" -C bin
out=$(bin/rotate --version)
[ "$out" = "rotate $version" ] || fail "--version printed '$out', expected 'rotate $version'"
echo "version: $out"

# 3. Smoke check in an empty environment.
mkdir run
cp "$fixture" run/report.ndjson
set +e
(cd run && env -i HOME="$work/run" PATH=/usr/bin:/bin "$work/bin/rotate" plan report.ndjson) \
  >plan.out 2>plan.err
code=$?
set -e
cat plan.out plan.err
[ "$code" -eq 0 ] || fail "plan exited $code, expected 0"
grep -q "Dry run: nothing was changed." plan.out || fail "no dry-run line"
grep -q "^Skipped:" plan.out || fail "no skipped findings"
grep -q "0 to rotate" plan.out || fail "a fixture finding was planned for rotation"
# Each provider is registered: findings are invalid or unknown, never
# unsupported (v0.0.1 shipped with no providers and said "unsupported").
if grep -q "unsupported" plan.out; then
  fail "a fixture finding is unsupported: is every provider registered?"
fi
if grep -qi "panicked" plan.out plan.err; then
  fail "plan panicked"
fi
# Every Raw and RawV2 value in the fixture, and each part of a RawV2 pair.
secrets=$(grep -o '"RawV2*":"[^"]*"' "$fixture" | sed 's/^"RawV2*":"//; s/"$//' | tr ':' '\n' | sort -u)
for secret in $secrets; do
  if grep -qF -- "$secret" plan.out plan.err; then
    fail "plan output contains a fixture secret"
  fi
done
echo "smoke check: ok"
echo "verify-release: $tag ok"
