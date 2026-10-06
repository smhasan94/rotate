#!/usr/bin/env bash
# Installs rotate for the GitHub Action (SHA-198).
#
# With ROTATE_BINARY set, checks that binary runs and uses it. Otherwise
# downloads the release tarball for this runner and SHA256SUMS, checks the
# checksum, and installs the binary under $RUNNER_TEMP/rotate/bin. A
# checksum mismatch removes the download and fails before the binary is
# run. Writes `path=<binary>` to $GITHUB_OUTPUT.
#
# Environment:
#   ROTATE_VERSION       release to install, such as 0.2.0
#   ROTATE_BINARY        a binary to use instead of downloading one
#   ROTATE_RELEASE_BASE  where the release assets are (test hook); default
#                        https://github.com/smhasan94/rotate/releases/download/v$ROTATE_VERSION
#   RUNNER_TEMP          set by the runner
#
# Works with bash 3.2 and both GNU and BSD tools.
set -euo pipefail

# An error annotation, escaped so it stays one workflow command, then exit.
fail() {
  local message=$1
  message=${message//%/%25}
  message=${message//$'\r'/%0D}
  message=${message//$'\n'/%0A}
  printf '::error title=rotate install::%s\n' "$message" >&2
  exit "${2:-1}"
}

output() {
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"
  fi
}

[ -n "${RUNNER_TEMP:-}" ] || fail "RUNNER_TEMP is not set"

if [ -n "${ROTATE_BINARY:-}" ]; then
  # The path goes into GITHUB_OUTPUT, so no newline or other control
  # character; and it is never echoed into a workflow command.
  if [[ $ROTATE_BINARY =~ [[:cntrl:]] ]]; then
    fail "input rotate-binary: must not contain control characters" 2
  fi
  bin=$ROTATE_BINARY
  case $bin in
    /*) ;;
    *) bin="$PWD/$bin" ;;
  esac
  [ -f "$bin" ] && [ -x "$bin" ] || fail "input rotate-binary: not an executable file" 2
  "$bin" --version || fail "input rotate-binary: --version failed"
  output path "$bin"
  exit 0
fi

VERSION=${ROTATE_VERSION:-}
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] ||
  fail "input version: expected a release version such as 0.2.0" 2

# Keep in step with the README install block (tests/action.rs checks).
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) TARGET=x86_64-unknown-linux-gnu ;;
  Linux-aarch64) TARGET=aarch64-unknown-linux-gnu ;;
  Darwin-x86_64) TARGET=x86_64-apple-darwin ;;
  Darwin-arm64) TARGET=aarch64-apple-darwin ;;
  *) fail "no rotate release binary for $(uname -s) $(uname -m)" ;;
esac
NAME="rotate-$VERSION-$TARGET"
BASE=${ROTATE_RELEASE_BASE:-https://github.com/smhasan94/rotate/releases/download/v$VERSION}
BASE=${BASE%/}

if command -v sha256sum >/dev/null 2>&1; then
  sha256_check() { sha256sum -c -; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_check() { shasum -a 256 -c -; }
else
  fail "neither sha256sum nor shasum is installed"
fi

mkdir -p "$RUNNER_TEMP/rotate"
download=$(mktemp -d "$RUNNER_TEMP/rotate/download.XXXXXX")
# Whatever happens, nothing downloaded is left behind.
trap 'rm -rf "$download"' EXIT

# Redirects stay on https (GitHub sends release downloads to its CDN);
# plain http only for a test server given in ROTATE_RELEASE_BASE.
case $BASE in
  https://*) protocols=(--proto '=https' --proto-redir '=https') ;;
  *) protocols=(--proto '=https,http' --proto-redir '=https,http') ;;
esac

fetch() {
  curl --disable --silent --show-error --fail --location --retry 2 \
    "${protocols[@]}" --output "$download/$1" "$BASE/$1" ||
    fail "could not download $BASE/$1"
}
fetch "$NAME.tar.gz"
fetch SHA256SUMS

# Exactly one well-formed line for the tarball: `<64 hex>  <name>` (or
# ` *<name>`, binary mode).
escaped=$(printf '%s' "$NAME.tar.gz" | sed 's/[.]/\\./g')
line=$(grep -E "[[:space:]][*]?$escaped\$" "$download/SHA256SUMS" || true)
count=$(printf '%s' "$line" | grep -c . || true)
[ "$count" -ne 0 ] || fail "SHA256SUMS has no line for $NAME.tar.gz"
[ "$count" -eq 1 ] || fail "SHA256SUMS has $count lines for $NAME.tar.gz; expected one"
well_formed="^[0-9a-fA-F]{64} [ *]$escaped\$"
[[ $line =~ $well_formed ]] || fail "SHA256SUMS has a malformed line for $NAME.tar.gz"
if ! (cd "$download" && printf '%s\n' "$line" | sha256_check >/dev/null 2>&1); then
  fail "checksum mismatch for $NAME.tar.gz: SHA256SUMS does not match the download; nothing was installed"
fi
echo "checksum ok: $NAME.tar.gz"

tar -xzf "$download/$NAME.tar.gz" -C "$download" rotate ||
  fail "$NAME.tar.gz has no rotate binary"
mkdir -p "$RUNNER_TEMP/rotate/bin"
bin="$RUNNER_TEMP/rotate/bin/rotate"
install -m 0755 "$download/rotate" "$bin"

reported=$("$bin" --version) || fail "rotate --version failed"
echo "$reported"
[ "$reported" = "rotate $VERSION" ] ||
  fail "expected 'rotate $VERSION' from the downloaded binary"
output path "$bin"
