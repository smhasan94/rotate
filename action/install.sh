#!/usr/bin/env bash
# Installs rotate for the GitHub Action (SHA-198).
#
# With ROTATE_BINARY set, checks that binary runs and uses it. Otherwise
# downloads the release tarball for this runner and SHA256SUMS, checks the
# checksum, checks the tarball's build provenance with `gh attestation
# verify` (SHA-389), and installs the binary under $RUNNER_TEMP/rotate/bin.
# A checksum mismatch or a failed attestation check removes the download
# and fails before the binary is run. Writes `path=<binary>` to
# $GITHUB_OUTPUT.
#
# Environment:
#   ROTATE_VERSION       release to install, such as 0.2.0
#   ROTATE_BINARY        a binary to use instead of downloading one
#   ROTATE_VERIFY_ATTESTATION
#                        auto (also when empty), true or false. auto checks
#                        the attestation when it can and otherwise prints a
#                        notice saying why not; true fails with exit 2,
#                        before downloading, when it cannot; false skips it
#   GH_TOKEN             token for gh (the workflow token); handed to gh
#                        only, through its environment. Empty: the
#                        attestation cannot be checked
#   ROTATE_RELEASE_BASE  where the release assets are (test hook); default
#                        https://github.com/smhasan94/rotate/releases/download/v$ROTATE_VERSION
#   ROTATE_ATTEST_BACKOFF  seconds to wait before each retry of a failed
#                        `gh attestation verify` (test hook); default "2 5",
#                        so three tries
#   RUNNER_TEMP, GITHUB_SERVER_URL  set by the runner
#
# Works with bash 3.2 and both GNU and BSD tools.
set -euo pipefail

REPO=smhasan94/rotate
# The workflow that builds, attests and publishes a release.
SIGNER_WORKFLOW=$REPO/.github/workflows/release.yml

# gh gets the token in its own environment; nothing else this script runs,
# the downloaded binary included, sees it.
gh_token=${GH_TOKEN:-}
unset GH_TOKEN

# An error annotation, escaped so it stays one workflow command, then exit.
fail() {
  local message=$1
  message=${message//%/%25}
  message=${message//$'\r'/%0D}
  message=${message//$'\n'/%0A}
  printf '::error title=rotate install::%s\n' "$message" >&2
  exit "${2:-1}"
}

notice() {
  local message=$1
  message=${message//%/%25}
  message=${message//$'\r'/%0D}
  message=${message//$'\n'/%0A}
  printf '::notice title=rotate install::%s\n' "$message" >&2
}

output() {
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"
  fi
}

# Whether release $1 has attestations: those after 0.3.0, the last one
# published before the release workflow attested (SHA-389). The
# pre-release suffix does not count, so 0.4.0-rc.1 has them. No API
# request.
attested_version() {
  local core=${1%%-*}
  local major=${core%%.*} rest=${core#*.}
  local minor=${rest%%.*} patch=${rest#*.}
  major=$((10#$major))
  minor=$((10#$minor))
  patch=$((10#$patch))
  [ "$major" -gt 0 ] || [ "$minor" -gt 3 ] || { [ "$minor" -eq 3 ] && [ "$patch" -gt 0 ]; }
}

# Why the attestation of release $1 cannot be checked here, or nothing
# when it can.
attestation_unavailable() {
  local help flag
  if ! attested_version "$1"; then
    echo "rotate $1 was released before 0.4.0, the first release with attestations"
  elif [ -n "${GITHUB_SERVER_URL:-}" ] && [ "$GITHUB_SERVER_URL" != https://github.com ]; then
    # GHES or GHE.com: the workflow token cannot read github.com.
    echo "this runner is not on github.com, so the workflow token cannot read the attestation there"
  elif ! command -v gh >/dev/null 2>&1; then
    echo "gh is not installed"
  elif [ -z "$gh_token" ]; then
    # Rather than an authentication error that reads like tampering.
    echo "GH_TOKEN is empty, so gh has no token to read the attestation with"
  else
    # An old gh has no `attestation` command, or lacks a flag used below.
    help=$(GH_NO_UPDATE_NOTIFIER=1 gh attestation verify --help 2>/dev/null) || help=
    for flag in --cert-identity --deny-self-hosted-runners; do
      case $help in
        *"$flag"*) ;;
        *)
          echo "this gh has no gh attestation verify $flag; update gh"
          return 0
          ;;
      esac
    done
  fi
}

[ -n "${RUNNER_TEMP:-}" ] || fail "RUNNER_TEMP is not set"

ATTESTATION=${ROTATE_VERIFY_ATTESTATION:-auto}
case $ATTESTATION in
  auto | true | false) ;;
  *) fail "input verify-attestation: must be auto, true or false" 2 ;;
esac
BACKOFF=${ROTATE_ATTEST_BACKOFF:-2 5}
[[ $BACKOFF =~ ^([0-9]{1,3}( [0-9]{1,3})*)?$ ]] ||
  fail "ROTATE_ATTEST_BACKOFF: expected seconds separated by spaces" 2

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
# At most 9 digits a component, so the version gate's arithmetic never
# overflows.
[[ $VERSION =~ ^[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}(-[0-9A-Za-z.]+)?$ ]] ||
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
BASE=${ROTATE_RELEASE_BASE:-https://github.com/$REPO/releases/download/v$VERSION}
BASE=${BASE%/}

# SHA-389: decided before anything is downloaded, so `true` fails first.
unavailable=
if [ "$ATTESTATION" != false ]; then
  unavailable=$(attestation_unavailable "$VERSION")
fi
if [ "$ATTESTATION" = true ] && [ -n "$unavailable" ]; then
  fail "input verify-attestation: is true, but the attestation of $NAME.tar.gz cannot be checked: $unavailable" 2
fi

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

# Build provenance (SHA-389): signed by release.yml in this repository at
# exactly this version's tag, on a GitHub-hosted runner. gh's output goes
# to the log; the token only to gh's environment. A failure is retried
# after each wait in BACKOFF (a flaky API or Sigstore TUF fetch), then
# fails the step.
verify_attestation() {
  GH_TOKEN=$gh_token GH_HOST=github.com GH_PROMPT_DISABLED=1 GH_NO_UPDATE_NOTIFIER=1 \
    gh attestation verify "$download/$NAME.tar.gz" \
    --repo "$REPO" \
    --cert-identity "https://github.com/$SIGNER_WORKFLOW@refs/tags/v$VERSION" \
    --deny-self-hosted-runners 2>&1
}
if [ "$ATTESTATION" = false ]; then
  :
elif [ -n "$unavailable" ]; then
  notice "The attestation of $NAME.tar.gz was not checked: $unavailable. Its checksum matches SHA256SUMS, which comes from the same release. Set verify-attestation: true to fail instead, or false to skip this notice."
else
  verified=false
  for delay in $BACKOFF -; do
    if verify_attestation; then
      verified=true
      break
    fi
    [ "$delay" != - ] || break
    echo "attestation check failed for $NAME.tar.gz; retrying in ${delay}s"
    sleep "$delay"
  done
  $verified || fail "attestation check failed for $NAME.tar.gz; nothing was installed"
  echo "attestation ok: $NAME.tar.gz"
fi

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
