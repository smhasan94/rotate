#!/usr/bin/env bash
# Runs the live GitHub tests (SHA-268) from this machine:
#
#   bash scripts/live-run.sh
#
# Asks for the rotate-live-tests token (hidden input; never stored or
# printed), then runs every live_github test against the test repository
# that scripts/live-setup.sh created. Takes about 5 minutes: each check
# dispatches a workflow in the test repository and waits for it.
#
# ROTATE_LIVE_GITHUB_REPO overrides the test repository
# (default <your login>/rotate-live).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

fail() {
  echo "live-run: FAILED: $*" >&2
  exit 1
}

command -v gh >/dev/null 2>&1 || fail "the gh CLI is not installed (brew install gh)"
cargo=cargo
[ -x "$HOME/.cargo/bin/cargo" ] && cargo="$HOME/.cargo/bin/cargo"
repo=${ROTATE_LIVE_GITHUB_REPO:-"$(gh api user --jq .login)/rotate-live"}

printf "Paste the rotate-live-tests token and press Enter (nothing will show): "
read -rs token
echo
[ -n "$token" ] || fail "no token entered"

echo "Running the live GitHub tests against $repo (about 5 minutes) ..."
ROTATE_LIVE_TESTS=1 \
  ROTATE_GITHUB_TOKEN="$token" \
  ROTATE_LIVE_GITHUB_TOKEN="$token" \
  ROTATE_LIVE_GITHUB_REPO="$repo" \
  RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-1.99.0} \
  "$cargo" test --all-features -- --ignored live_github --nocapture
