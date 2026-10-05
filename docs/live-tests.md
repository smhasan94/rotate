# Live tests: setup

The default test suite mocks every API with wiremock. The live tests check
those mocks against the real GitHub REST API. They run only when
`ROTATE_LIVE_TESTS=1` is set. In CI they run only from the manual `live.yml`
workflow, and every run waits for the maintainer's approval.

The AWS live test (IAM, STS and Secrets Manager) is not built yet. It needs
an AWS account and is tracked in SHA-317. Its setup steps will be added to
this page with it.

This page is the one-time setup. Work through it top to bottom. Each step
ends with a **Check**. Do not go on to the next step until the check passes.
Everything you create is throwaway and used only by these tests. Nothing here
touches a real workload.

## What the tests change

Each run overwrites one Actions secret in a private test repository. It then
dispatches a workflow there that prints a fingerprint of the secret (never
the value), and finally restores the secret.

If a run fails partway, the harness still restores the secret. If that
restore itself fails, the run's error ends with `left behind: ...`, and
[Cleanup by hand](#cleanup-by-hand) says what to do.

## Quick way: the setup script

`scripts/live-setup.sh` does steps 1 to 3 below and runs every check. Run
it in a terminal from any directory:

```sh
bash scripts/live-setup.sh
```

It stops once, for the token you create in your browser (step 2), and
prints the `live setup done` line at the end. It is safe to re-run. The
steps below are the same work done by hand.

## Before you start

You need:

- The `gh` CLI logged in as the owner of `smhasan94/rotate`.
- `shasum` (on macOS by default).
- About 15 minutes.

Cost: each run uses about 2 minutes of GitHub Actions on the private test
repository, which is well inside the free monthly allowance. The workflow on
`smhasan94/rotate` runs on a public repository, so its minutes are free.

Set this value first. The commands below use it, so run every step in the
same terminal.

```sh
export LIVE_GH_OWNER=$(gh api user --jq .login)   # owner of the test repo
echo "$LIVE_GH_OWNER"
```

**Check:** the echo prints your GitHub login.

Secret values are typed with `read -rs` or at a `gh` prompt, which do not
echo them, so they stay out of your shell history and scrollback. The
commands work in zsh and bash.

## Step 1: GitHub test repository

The test overwrites a secret in this repository. To confirm the new value
arrived, it dispatches a workflow that prints the first 16 hex digits of the
secret's `SHA-256` digest. That is the same shape as rotate's fingerprints.
GitHub also masks the value itself in logs.

```sh
gh repo create "$LIVE_GH_OWNER/rotate-live" --private --add-readme
gh repo clone "$LIVE_GH_OWNER/rotate-live" /tmp/rotate-live
mkdir -p /tmp/rotate-live/.github/workflows
cat > /tmp/rotate-live/.github/workflows/fingerprint.yml <<'EOF'
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
git -C /tmp/rotate-live add .github/workflows/fingerprint.yml
git -C /tmp/rotate-live commit -m "ci: add fingerprint workflow"
git -C /tmp/rotate-live push
rm -rf /tmp/rotate-live

gh secret set ROTATE_LIVE_CANARY --repo "$LIVE_GH_OWNER/rotate-live" --body placeholder
```

The workflow must be on the default branch, because `workflow_dispatch` only
sees workflows there. The secret's name must not start with `GITHUB_`,
because GitHub rejects those names.

**Check:** dispatch the workflow once by hand. The fingerprint it prints
matches the one you compute locally.

```sh
gh workflow run fingerprint.yml --repo "$LIVE_GH_OWNER/rotate-live" \
  -f nonce=setup-check -f secret_name=ROTATE_LIVE_CANARY
sleep 10
RUN_ID=$(gh run list --repo "$LIVE_GH_OWNER/rotate-live" --workflow fingerprint.yml \
  --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$RUN_ID" --repo "$LIVE_GH_OWNER/rotate-live" --exit-status
gh run view "$RUN_ID" --repo "$LIVE_GH_OWNER/rotate-live" --log \
  | grep -o 'fingerprint=sha256:[0-9a-f]*' | tail -1
printf 'fingerprint=sha256:%s\n' "$(printf placeholder | shasum -a 256 | cut -c1-16)"
```

The last two lines printed are the same. The run's title in the Actions tab
is `fingerprint setup-check`.

## Step 2: fine-grained personal access token

The test acts on the repository with this token. Create it on github.com:

1. Go to Settings, then Developer settings, then Personal access tokens, then
   Fine-grained tokens, then Generate new token.
2. Name: `rotate-live-tests`. Expiration: 90 days. Put the expiry date in
   your calendar; once it passes, the live run fails with a 401.
3. Resource owner: your account (`$LIVE_GH_OWNER`). Repository access: Only
   select repositories, then `rotate-live` only.
4. Repository permissions:
   - Actions: Read and write (dispatch, list runs, read logs)
   - Secrets: Read and write
   - Metadata: Read-only (selected automatically)
5. Generate the token, and copy it straight into your password manager.

**Check:** the token can read the repository's secrets public key and the
workflow, and cannot see any other repository. Paste the token after the
prompt.

```sh
echo "rotate-live-tests token:"; read -rs LIVE_PAT
GH_TOKEN="$LIVE_PAT" gh api "repos/$LIVE_GH_OWNER/rotate-live/actions/secrets/public-key" --jq .key_id
GH_TOKEN="$LIVE_PAT" gh api "repos/$LIVE_GH_OWNER/rotate-live/actions/workflows/fingerprint.yml" --jq .state
GH_TOKEN="$LIVE_PAT" gh api repos/smhasan94/rotate/actions/secrets --silent; echo "exit $?"
unset LIVE_PAT
```

The first command prints a key id and the second prints `active`. The third
fails with a 403 or 404, followed by a nonzero `exit`.

## Step 3: the `live-tests` environment

The `live.yml` workflow on `smhasan94/rotate` reads its credentials from an
environment called `live-tests`. That environment requires your approval
before every run, so the credentials are never used without you.

Create the environment with yourself as the required reviewer. Self-review
must be allowed, because you are also the one who dispatches the run.

```sh
gh api -X PUT repos/smhasan94/rotate/environments/live-tests --input - <<EOF
{
  "reviewers": [{ "type": "User", "id": $(gh api user --jq .id) }],
  "prevent_self_review": false,
  "deployment_branch_policy": null
}
EOF
```

Set the secret. `gh secret set` without `--body` prompts for the value, so it
stays out of your shell history. Paste the token from your password manager.

```sh
gh secret set ROTATE_LIVE_GITHUB_TOKEN --repo smhasan94/rotate --env live-tests
```

Set the variable. It is a name, not a secret.

```sh
gh variable set ROTATE_LIVE_GITHUB_REPO --repo smhasan94/rotate --env live-tests \
  --body "$LIVE_GH_OWNER/rotate-live"
```

Two more variables are optional. When they are not set, the tests use these
defaults: `ROTATE_LIVE_GITHUB_SECRET` (`ROTATE_LIVE_CANARY`) and
`ROTATE_LIVE_GITHUB_WORKFLOW` (`fingerprint.yml`).

**Check:**

```sh
gh api repos/smhasan94/rotate/environments/live-tests --jq '[.protection_rules[].type]'
gh secret list   --repo smhasan94/rotate --env live-tests
gh variable list --repo smhasan94/rotate --env live-tests
```

The protection rules include `required_reviewers`. The secret list has
exactly `ROTATE_LIVE_GITHUB_TOKEN`. The variable list has
`ROTATE_LIVE_GITHUB_REPO` set to `<you>/rotate-live`.

## Step 4 (later): run locally

This step works only once the tests exist (SHA-268). Until then, skip it.

To run the live tests from your machine, export the same names in one shell
session. Do not put them in a dotfile or in a `.env` file in the repository.
Two names carry the token: the consumer reads `ROTATE_GITHUB_TOKEN`, and the
kept provider check reads `ROTATE_LIVE_GITHUB_TOKEN`. Set both.

```sh
echo "rotate-live-tests token:"; read -rs ROTATE_GITHUB_TOKEN
export ROTATE_GITHUB_TOKEN ROTATE_LIVE_GITHUB_TOKEN="$ROTATE_GITHUB_TOKEN"
export ROTATE_LIVE_GITHUB_REPO="$LIVE_GH_OWNER/rotate-live"

ROTATE_LIVE_TESTS=1 RUSTUP_TOOLCHAIN=1.99.0 cargo test --all-features -- --ignored live_github
```

To test the restore path by hand, set `ROTATE_LIVE_FAIL_AFTER=update`. The
run then fails on purpose right after it overwrites the secret.

## Done

When every check has passed, report the setup as done with these values.
None of them is a secret.

```
live setup done: test_repo=<owner>/rotate-live pat_expires=<date>
```

## Manual checks that stay out of the workflow

These live tests already exist and are not part of `live.yml`'s default
scope. Each one skips with `skipped: <NAME> not set` unless you set its
variables yourself.

| Test | Variables | Why it is manual |
| --- | --- | --- |
| `live_github_check_valid_and_scope` | `ROTATE_LIVE_GITHUB_TOKEN` | Read-only. It also runs in `live.yml`, with the environment's token. |
| `live_github_revoke` | `ROTATE_LIVE_GITHUB_REVOKE_TOKEN` | Revokes the token it is given, so each run needs a new one. |
| `live_aws_check_valid_and_scope`, `live_aws_rotate_round_trip` | `ROTATE_LIVE_AWS_ACCESS_KEY_ID`, `ROTATE_LIVE_AWS_SECRET_ACCESS_KEY` | Need an AWS account. Replaced by the SHA-317 test. |
| `live_secrets_manager_find_is_read_only` | `ROTATE_LIVE_SM_SECRET` | Needs an AWS account. Replaced by the SHA-317 test. |
| npm (two tests) | `ROTATE_LIVE_NPM_TOKEN`, `ROTATE_LIVE_NPM_REVOKE_TOKEN` | Deleting a token needs an `npm login` session and often a one-time password. |
| OpenAI (two tests) | `ROTATE_LIVE_OPENAI_KEY` | Needs an admin key on a real organization, and creating keys has side effects. |

## Cleanup by hand

When a run ends with `left behind: ...`, put the secret back:

```sh
gh secret set ROTATE_LIVE_CANARY --repo "$LIVE_GH_OWNER/rotate-live" --body placeholder
```

## Tearing it all down

To remove the whole setup (`gh repo delete` needs the `delete_repo` scope;
`gh auth refresh -s delete_repo` adds it):

```sh
gh api -X DELETE repos/smhasan94/rotate/environments/live-tests
gh repo delete "$LIVE_GH_OWNER/rotate-live" --yes
```

Then delete the `rotate-live-tests` token under Settings, Developer settings,
Fine-grained tokens.
