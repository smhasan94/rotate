#!/usr/bin/env bash
# One-time setup for the live GitHub tests (SHA-268). Automates
# docs/live-tests.md steps 1 to 3:
#
#   bash scripts/live-setup.sh
#
# 1. Creates the private test repository <you>/rotate-live with the
#    fingerprint workflow and the ROTATE_LIVE_CANARY secret, then dispatches
#    the workflow once and checks the fingerprint it prints.
# 2. Asks for the fine-grained token you create in the browser (hidden
#    input) and checks it can reach rotate-live and nothing else.
# 3. Creates the live-tests environment on smhasan94/rotate with you as
#    required reviewer, stores the token and the repo variable, and checks
#    them.
#
# Safe to re-run: every step skips or overwrites what already exists. The
# token is held only in this shell's memory and is never printed or written
# to disk.
#
# ROTATE_REPO overrides the main repository (default smhasan94/rotate).
set -euo pipefail

repo=${ROTATE_REPO:-smhasan94/rotate}
canary=ROTATE_LIVE_CANARY
workflow=fingerprint.yml

fail() {
  echo
  echo "live-setup: FAILED: $*" >&2
  exit 1
}

step() {
  echo
  echo "== $* =="
}

ok() {
  echo "   ok: $*"
}

pat=""
trap 'pat=""' EXIT

# ---------------------------------------------------------------- step 0
step "Step 0: checking gh"
command -v gh >/dev/null 2>&1 || fail "the gh CLI is not installed (brew install gh)"
gh auth status >/dev/null 2>&1 || fail "gh is not logged in (run: gh auth login)"
owner=$(gh api user --jq .login)
ok "logged in as $owner"
admin=$(gh api "repos/$repo" --jq .permissions.admin 2>/dev/null || echo false)
[ "$admin" = "true" ] || fail "$owner is not an admin of $repo"
ok "admin of $repo"
test_repo="$owner/rotate-live"

# ---------------------------------------------------------------- step 1
step "Step 1: test repository $test_repo"
if gh api "repos/$test_repo" --silent 2>/dev/null; then
  ok "repository already exists"
else
  gh repo create "$test_repo" --private --add-readme >/dev/null
  ok "created private repository"
fi

workflow_yaml=$(cat <<'EOF'
name: fingerprint
run-name: fingerprint ${{ inputs.nonce }}
on:
  workflow_dispatch:
    inputs:
      nonce:
        description: "Set by the live test"
        required: true
        type: string
      secret_name:
        description: "Repository secret to fingerprint"
        required: true
        type: string
permissions: {}
jobs:
  fingerprint:
    runs-on: ubuntu-latest
    timeout-minutes: 2
    steps:
      - env:
          VALUE: ${{ secrets[inputs.secret_name] }}
        run: printf 'fingerprint=sha256:%s\n' "$(printf '%s' "$VALUE" | sha256sum | cut -c1-16)"
EOF
)
path=".github/workflows/$workflow"
existing_sha=$(gh api "repos/$test_repo/contents/$path" --jq .sha 2>/dev/null || true)
content_b64=$(printf '%s\n' "$workflow_yaml" | base64 | tr -d '\n')
if [ -n "$existing_sha" ]; then
  gh api -X PUT "repos/$test_repo/contents/$path" --silent \
    -f message="ci: update fingerprint workflow" -f content="$content_b64" -f sha="$existing_sha"
  ok "workflow file updated"
else
  gh api -X PUT "repos/$test_repo/contents/$path" --silent \
    -f message="ci: add fingerprint workflow" -f content="$content_b64"
  ok "workflow file added"
fi

gh secret set "$canary" --repo "$test_repo" --body placeholder >/dev/null
ok "secret $canary set to the placeholder"

echo "   checking the workflow (takes about a minute)..."
nonce="setup-$(date +%s)"
dispatched=false
for _ in 1 2 3 4 5 6; do
  if gh workflow run "$workflow" --repo "$test_repo" \
    -f nonce="$nonce" -f secret_name="$canary" >/dev/null 2>&1; then
    dispatched=true
    break
  fi
  sleep 5 # a just-added workflow takes a few seconds to become dispatchable
done
$dispatched || fail "could not dispatch $workflow in $test_repo"

run_id=""
for _ in $(seq 1 24); do
  run_id=$(gh run list --repo "$test_repo" --workflow "$workflow" --limit 20 \
    --json databaseId,displayTitle \
    --jq ".[] | select(.displayTitle == \"fingerprint $nonce\") | .databaseId" | head -1)
  [ -n "$run_id" ] && break
  sleep 5
done
[ -n "$run_id" ] || fail "the dispatched run did not appear in $test_repo"
gh run watch "$run_id" --repo "$test_repo" --exit-status >/dev/null \
  || fail "the fingerprint run failed: gh run view $run_id --repo $test_repo"

got=""
for _ in 1 2 3 4 5 6; do
  got=$(gh run view "$run_id" --repo "$test_repo" --log 2>/dev/null \
    | grep -o 'fingerprint=sha256:[0-9a-f]*' | tail -1 || true)
  [ -n "$got" ] && break
  sleep 5 # logs can lag a few seconds behind the run finishing
done
want="fingerprint=sha256:$(printf placeholder | shasum -a 256 | cut -c1-16)"
[ "$got" = "$want" ] || fail "fingerprint mismatch: workflow printed '$got', expected '$want'"
ok "workflow fingerprint matches ($want)"

# ---------------------------------------------------------------- step 2
step "Step 2: fine-grained token (in your browser)"
cat <<EOF
   Create the token on github.com with exactly these settings:

     Token name ........ rotate-live-tests
     Expiration ........ 90 days
     Resource owner .... $owner
     Repository access . Only select repositories -> rotate-live
     Permissions ....... Repository permissions:
                           Actions -> Read and write
                           Secrets -> Read and write

   Click "Generate token" and copy it (save it in your password manager too).

EOF
printf "   Press Enter to open the token page in your browser..."
read -r _
open "https://github.com/settings/personal-access-tokens/new" 2>/dev/null \
  || echo "   open https://github.com/settings/personal-access-tokens/new"
echo
printf "   Paste the token here and press Enter (nothing will show): "
read -rs pat
echo
[ -n "$pat" ] || fail "no token entered"

GH_TOKEN="$pat" gh api "repos/$test_repo/actions/secrets/public-key" --silent 2>/dev/null \
  || fail "the token cannot read $test_repo secrets: check Secrets is Read and write and the repository is rotate-live"
ok "token can manage secrets on $test_repo"
state=$(GH_TOKEN="$pat" gh api "repos/$test_repo/actions/workflows/$workflow" --jq .state 2>/dev/null || true)
[ "$state" = "active" ] \
  || fail "the token cannot see the workflow: check Actions is Read and write"
ok "token can see the workflow"
if GH_TOKEN="$pat" gh api "repos/$repo/actions/secrets" --silent 2>/dev/null; then
  fail "the token can reach $repo: recreate it with 'Only select repositories -> rotate-live'"
fi
ok "token cannot reach $repo (correct)"
expires=$(GH_TOKEN="$pat" gh api -i "repos/$test_repo" 2>/dev/null \
  | grep -i '^github-authentication-token-expiration:' | awk '{print $2}' | tr -d '\r' || true)
[ -n "$expires" ] && ok "token expires $expires"

# ---------------------------------------------------------------- step 3
step "Step 3: live-tests environment on $repo"
my_id=$(gh api user --jq .id)
gh api -X PUT "repos/$repo/environments/live-tests" --silent --input - <<EOF
{
  "reviewers": [{ "type": "User", "id": $my_id }],
  "prevent_self_review": false,
  "deployment_branch_policy": null
}
EOF
ok "environment live-tests with you as required reviewer"

# stdin, not --body, so the token never appears in a process listing
printf '%s' "$pat" | gh secret set ROTATE_LIVE_GITHUB_TOKEN --repo "$repo" --env live-tests >/dev/null
pat=""
ok "secret ROTATE_LIVE_GITHUB_TOKEN stored"
gh variable set ROTATE_LIVE_GITHUB_REPO --repo "$repo" --env live-tests --body "$test_repo" >/dev/null
ok "variable ROTATE_LIVE_GITHUB_REPO = $test_repo"

rules=$(gh api "repos/$repo/environments/live-tests" --jq '[.protection_rules[].type] | join(",")')
case "$rules" in
  *required_reviewers*) ok "approval gate is on" ;;
  *) fail "the environment has no required_reviewers rule (got: $rules)" ;;
esac
gh secret list --repo "$repo" --env live-tests | grep -q '^ROTATE_LIVE_GITHUB_TOKEN' \
  || fail "ROTATE_LIVE_GITHUB_TOKEN is missing from the environment"
var=$(gh variable get ROTATE_LIVE_GITHUB_REPO --repo "$repo" --env live-tests)
[ "$var" = "$test_repo" ] || fail "ROTATE_LIVE_GITHUB_REPO is '$var', expected '$test_repo'"
ok "environment checks pass"

# ---------------------------------------------------------------- done
step "All done. Paste this line back to Claude:"
echo
echo "live setup done: test_repo=$test_repo pat_expires=${expires:-<check the date on github.com>}"
echo
