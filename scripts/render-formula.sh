#!/usr/bin/env bash
# Renders the Homebrew formula for a release (SHA-339).
#
#   scripts/render-formula.sh <version> <SHA256SUMS> [template] > rotate.rb
#
# Fills packaging/homebrew/rotate.rb.tmpl (or the given template) with the
# version and the checksum of each of the four release tarballs
# rotate-<version>-<target>.tar.gz, read from SHA256SUMS (`sha256sum`
# output; a leading `*` binary marker is accepted). Fails, naming every
# missing target, unless SHA256SUMS has exactly one well-formed line for
# each, and prints nothing on stdout when it fails.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
targets="aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu"

fail() {
  echo "render-formula: $*" >&2
  exit 1
}

[ $# -ge 2 ] && [ $# -le 3 ] || fail "usage: scripts/render-formula.sh <version> <SHA256SUMS> [template]"
version=${1#v}
sums=$2
template=${3:-$root/packaging/homebrew/rotate.rb.tmpl}

# Validated here so the values can go into sed unescaped.
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]] ||
  fail "version '$version' is not X.Y.Z"
[ -f "$sums" ] || fail "no such file: $sums"
[ -f "$template" ] || fail "no such template: $template"

errors=()
script=()
for target in $targets; do
  name="rotate-$version-$target.tar.gz"
  sums_for=$(awk -v n="$name" '{ f = $2; sub(/^\*/, "", f) } f == n { print $1 }' "$sums")
  count=$(printf '%s' "$sums_for" | grep -c . || true)
  if [ "$count" -eq 0 ]; then
    errors+=("missing target $target: SHA256SUMS has no line for $name")
    continue
  fi
  if [ "$count" -gt 1 ]; then
    errors+=("target $target: SHA256SUMS has $count lines for $name")
    continue
  fi
  if ! [[ "$sums_for" =~ ^[0-9a-f]{64}$ ]]; then
    errors+=("target $target: the checksum for $name is not 64 lowercase hex digits")
    continue
  fi
  key=$(printf '%s' "$target" | tr 'a-z-' 'A-Z_')
  script+=(-e "s/@SHA256_${key}@/$sums_for/g")
done

if [ ${#errors[@]} -gt 0 ]; then
  for error in "${errors[@]}"; do
    echo "render-formula: $error" >&2
  done
  exit 1
fi

formula=$(sed -e "s/@VERSION@/$version/g" "${script[@]}" "$template")
if left=$(grep -o '@[A-Z0-9_]*@' <<<"$formula"); then
  fail "placeholders left in the formula: $(sort -u <<<"$left" | tr '\n' ' ')"
fi
printf '%s\n' "$formula"
