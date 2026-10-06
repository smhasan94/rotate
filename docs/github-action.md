# GitHub Action: plan and apply secret-scanning alerts

rotate ships a composite GitHub Action, `action.yml` at the root of this
repository. Given a secret-scanning alert number, or none, it fetches the
alerts with GitHub's REST API, pipes them into
`rotate plan --stdin --format github-alert`, and writes the plan to the job
summary: what would be created, updated and revoked for each leaked secret,
and why anything was skipped.

In its default mode, `plan`, it changes nothing: `rotate plan` makes no
state-changing call to any provider or consumer, and the Action only sends
GET requests to the GitHub API. With `mode: apply`, in a second job that a
reviewer must approve, it runs `rotate apply` on the rotations the plan job
listed: create the replacement, update the consumers, verify, wait out the
overlap window, revoke the old secret
([Apply behind an approval](#apply-behind-an-approval)).

What it does not do: it does not host a webhook receiver, comment on pull
requests or issues, page through more than 100 alerts, resume a pending
revoke in a later workflow run, or run on Windows runners.

## Quick start

```yaml
- uses: actions/checkout@v4 # for rotate.yaml
- uses: smhasan94/rotate@vX.Y.Z # pin a release tag or a full commit SHA
  with:
    alert-number: "42"
    alerts-token: ${{ secrets.ROTATE_ALERTS_TOKEN }}
  env:
    ROTATE_GITHUB_TOKEN: ${{ secrets.ROTATE_GITHUB_TOKEN }}
```

The Action is in the repository from the release after 0.2.0. Pin a tag
(`@vX.Y.Z`) or, better, the full commit SHA of that tag: a commit SHA is
the only reference GitHub treats as immutable. There is no floating `v1`
tag before rotate 1.0. With a tag, `version` defaults to the same release,
so `smhasan94/rotate@vX.Y.Z` runs rotate X.Y.Z.

## How the alert reaches rotate

GitHub cannot start a workflow on a `secret_scanning_alert` event: it is a
webhook event only, and its payload has no `secret` field. A workflow
learns the alert number some other way (below) and the Action fetches the
alert with `GET /repos/{owner}/{repo}/secret-scanning/alerts/{number}`,
which returns the value.

The response goes from `curl` straight into rotate's standard input
through a pipe. The value never sits in a file, a shell variable, an
environment variable or `jq`, so there is nothing for `::add-mask::` to
mask and the Action does not use it. rotate reads the alert into a
zeroized buffer and every line it prints is redacted; the plan, the
summary, the outputs and the state file hold fingerprints and references
only. `tests/action.rs` runs the Action's scripts with a canary secret at
the highest verbosity and checks that it appears in none of the step's
output, the summary, `GITHUB_OUTPUT`, `plan.json`, the state file, the
audit log, or any file name or content under `RUNNER_TEMP`.

With alert numbers, the Action also fetches the open
`aws_access_key_id` alerts, so an `aws_secret_access_key` alert can be
paired with its key id ([report-formats.md](report-formats.md#github-secret-scanning-alerts)).
Unpaired key-id alerts then show up as skipped, `not rotatable`.

## The alerts token

The workflow's `GITHUB_TOKEN` cannot read secret-scanning alerts: the
`security-events` permission does not cover them and there is no
`secret-scanning-alerts` permission in `permissions:`. Pass a token in
`alerts-token`:

- **A GitHub App installation token (recommended).** Create an App with the
  repository permission "Secret scanning alerts: read" and nothing else,
  install it on the repository, and mint a short-lived token in the
  workflow with `actions/create-github-app-token`:

  ```yaml
  - uses: actions/create-github-app-token@v2
    id: app
    with:
      app-id: ${{ vars.ROTATE_APP_ID }}
      private-key: ${{ secrets.ROTATE_APP_KEY }}
  - uses: smhasan94/rotate@vX.Y.Z
    with:
      alerts-token: ${{ steps.app.outputs.token }}
  ```

- **A fine-grained personal access token**, limited to the repository,
  with "Secret scanning alerts: read" only, stored as a repository or
  environment secret. Its owner must be an administrator of the repository
  or organization. A classic token needs `repo` or `security_events`,
  which grant far more; avoid it.

When the API answers 401, 403 or 404, the step fails with the status and
"the token needs Secret scanning alerts: read; GITHUB_TOKEN cannot read
alerts", rotate is not run, and the job summary holds that message only.
A 404 can also mean the alert number does not exist or secret scanning is
not enabled.

## Operator credentials

`rotate plan` checks whether each leaked secret is still valid, describes
its scope and searches the consumers in `rotate.yaml`. Those read-only
calls use your operator credentials, which the Action does not take as
inputs: set them in the job as you would for rotate anywhere else
([config.md](config.md#precedence-and-environment-variables),
[permissions.md](permissions.md)).

| Provider or consumer | Credentials in the job |
| --- | --- |
| AWS IAM, AWS Secrets Manager | An OIDC role with the read-only actions in permissions.md, via `aws-actions/configure-aws-credentials`. |
| GitHub tokens | None: the credential revocation API needs no token. |
| GitHub Actions secrets | `ROTATE_GITHUB_TOKEN`, a token that can read the Actions secrets of the targets in `rotate.yaml`. |
| npm | `ROTATE_NPM_TOKEN`. |
| OpenAI | `OPENAI_ADMIN_KEY` (or the name in `providers.openai.admin_key_env`). |

Without a provider's credentials rotate cannot check that provider's
secrets; the plan lists them as skipped with the reason, and a consumer
search that fails is listed with its error.

## Security

**Take `rotate.yaml` from a trusted ref only.** The config decides where
rotate sends requests: `providers.github.api_url`, `providers.npm.registry`,
`providers.openai.api_url` and `providers.aws.endpoint_url` can point at
any https host ([config.md](config.md#endpoint-urls)). rotate checks a
leaked secret by calling its provider with it, and uses the operator
credentials in the job, so a `rotate.yaml` written by an attacker could
send both the leaked value and your operator tokens to the attacker's
host. The plan prints a warning for every endpoint that is not the
provider's default, but by then the requests have been made.

- Check out the default branch (the `actions/checkout` default for
  `workflow_dispatch`, `repository_dispatch` and `schedule`) and point
  `config` at a file in it.
- Never run the Action with credentials on `pull_request_target`, or
  after checking out a pull request's head or any other ref someone
  outside your team can write to.
- Keep `alerts-token` and the operator credentials in an environment or
  repository secret that pull requests from forks cannot read.

**What the download check proves.** `install.sh` compares the tarball with
the release's `SHA256SUMS`. Both files come from the same GitHub Release,
so the check detects a corrupted or truncated download, not a release
whose assets were replaced: whoever can replace the tarball can replace
`SHA256SUMS` too. The release workflow publishes no signature or build
attestation today. Until it does, pin the Action by commit SHA, or build
rotate yourself and pass it in `rotate-binary`. (Follow-up: publish build
provenance with `actions/attest-build-provenance` and have `install.sh`
check it with `gh attestation verify` when `gh` is available.)

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `alert-number` | `""` | Alert numbers, comma-separated, such as `42` or `42,43`. Empty: poll mode, the open alerts of the six supported types. |
| `repository` | `${{ github.repository }}` | `owner/repo` the alerts belong to. |
| `alerts-token` | required | Token with "Secret scanning alerts: read" (above). Not `GITHUB_TOKEN`. |
| `api-url` | `${{ github.api_url }}` | GitHub REST API base URL; set for GitHub Enterprise Server. `https`, or `http` to a loopback address only. |
| `version` | the release the Action is pinned to | rotate release to download. Ignored when `rotate-binary` is set. |
| `rotate-binary` | `""` | Path to a rotate binary to run instead of downloading one, for self-hosted runners and mirrors. |
| `config` | `rotate.yaml` | Path to `rotate.yaml`, relative to the workspace. A missing file is an error unless it is the default. Take it from a trusted ref only ([Security](#security)). |
| `mode` | `plan` | `plan` makes no change. `apply` applies the confirmed rotations; use it only in a job behind an environment approval ([Apply behind an approval](#apply-behind-an-approval)). |
| `verbose` | `0` | rotate's log verbosity, `0` to `3` (`-v` to `-vvv`). Logs are redacted at every level. |
| `overlap` | `""` | The overlap window between updating the consumers and revoking the old secret, such as `30m` or `1h30m` (`rotate --overlap`). Empty: `overlap_window` in `rotate.yaml`, else `0s`. |
| `confirm` | `""` | Apply only, required: the rotation ids to apply, comma-separated, each `rot-` and 8 hex digits. Pass the plan job's `rotation-ids` output. |
| `state-dir` | `""` | Apply only, required: the directory the plan job's state artifact was downloaded to. It holds `.rotate/state.json`, which maps the ids to the leaked secrets. |
| `force` | `false` | Apply only: `true` revokes the old secret even if some consumers could not be updated (`rotate --force`), recorded in the audit log. Never skips a failed create or verify. |
| `replacement-env` | `""` | Apply only: the name (not the value) of an environment variable holding a replacement you created by hand, for a provider in manual replacement mode (`rotate --replacement-from-env`). One rotation per run. |
| `max-wait` | `5h` | Apply only: the longest overlap window the step waits out. Keep it below the job's `timeout-minutes`. A longer window: no revoke, exit 3 with the revoke time. |
| `upload-audit` | `true` | Apply only: upload `.rotate/` of the state directory (audit log and state file) as the artifact `rotate-audit-<run id>-<attempt>`, kept 30 days. Set `false` on a public repository. |

Inputs reach the scripts through environment variables, never through
`run:` text, so a hostile `client_payload` cannot inject shell. They are
checked before anything is downloaded or fetched: an `alert-number` that is
not digits and commas, a `repository` that is not `owner/repo`, an empty
`alerts-token`, a `confirm` that is not rotation ids, an apply-only input
in plan mode, or an apply without `confirm` or `state-dir` fails the step
with exit code 2 and one line naming the input. The line never repeats the
value.

## Outputs

| Output | Description |
| --- | --- |
| `rotation-ids` | Plan: comma-separated rotation ids from the plan, such as `rot-1a2b3c4d,rot-5e6f7a8b`; empty when there is nothing to rotate. Pass it to the apply job's `confirm`. |
| `plan-path` | Plan: path of `plan.json`, the `rotate plan --json` output ([plan-schema.json](plan-schema.json)). Holds fingerprints and references only. |
| `summary-path` | Path of the Markdown the Action appended to the job summary. |
| `state-dir` | Directory holding `.rotate/state.json` and `.rotate/audit.jsonl` for this run, under `RUNNER_TEMP`. In the plan job, upload it as the state artifact. |
| `exit-code` | rotate's exit code, or the Action's own when rotate did not run (`1` when the alerts could not be fetched). |

Everything lives under `$RUNNER_TEMP/rotate/`, readable by the runner's
user only, and is discarded with the runner. The state directory and
`plan.json` hold no secret value but name your consumers and key ids, so
keep artifact retention short, and on a public repository, where anyone
with read access can download artifacts, turn `upload-audit` off.

## The job summary

For each rotation: the rotation id, the alert link, the provider, the
fingerprint, the scope identity, every consumer found (updatable or why
not), the replacement mode, the revoke action and the blockers. Then a
Skipped table with the alert link, the reason (`resolved`, `no secret`,
`invalid`, `unsupported`, `not rotatable`, ...) and the detail, and the
line "Dry run: nothing was changed." With no open alert in poll mode, it
says "No open secret-scanning alerts of the supported types." The same
Markdown is printed to the step log.

The step exits with rotate's exit code: 0 when the plan was made, even
with blockers or skipped alerts; 2 for a configuration error, whose
message is in the summary.

## Triggers

The Action does not care how the workflow started. Three patterns, all in
one caller workflow:

```yaml
name: rotate-alert
on:
  # 1. By hand, from the Actions tab or `gh workflow run`.
  workflow_dispatch:
    inputs:
      alert:
        description: Secret-scanning alert number (empty for all open alerts)
        required: false
        type: string
  # 2. From a webhook receiver (contract below).
  repository_dispatch:
    types: [secret-scanning-alert]
  # 3. On a schedule: poll the open alerts.
  schedule:
    - cron: "17 */6 * * *"

permissions:
  contents: read
  id-token: write # for the AWS role

jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4 # pin by SHA in your workflow
      - uses: actions/create-github-app-token@v2
        id: app
        with:
          app-id: ${{ vars.ROTATE_APP_ID }}
          private-key: ${{ secrets.ROTATE_APP_KEY }}
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/rotate-plan
          aws-region: us-east-1
      - id: rotate
        uses: smhasan94/rotate@vX.Y.Z # or a full commit SHA
        with:
          alert-number: ${{ inputs.alert || github.event.client_payload.alert.number || '' }}
          alerts-token: ${{ steps.app.outputs.token }}
        env:
          ROTATE_GITHUB_TOKEN: ${{ secrets.ROTATE_GITHUB_TOKEN }}
      - run: echo "to rotate: $IDS"
        env:
          IDS: ${{ steps.rotate.outputs.rotation-ids }}
```

1. **`workflow_dispatch`**: someone types the alert number from the
   security tab. Inputs hold at most 65535 characters.
2. **`repository_dispatch`**: a receiver you host turns the
   `secret_scanning_alert` webhook into a dispatch (contract below). The
   run uses the workflow file on the default branch.
3. **`schedule`**: no alert number, so the Action polls. The shortest
   interval is 5 minutes and GitHub may delay scheduled runs under load.

In poll mode the Action makes one request,
`GET /repos/{owner}/{repo}/secret-scanning/alerts?state=open&per_page=100&secret_type=aws_secret_access_key,aws_access_key_id,github_personal_access_token,github_oauth_access_token,npm_access_token,openai_api_key`,
and plans the first 100 open alerts of those six types. It does not page
further; with more than 100 open alerts, pass alert numbers.

## Apply behind an approval

`mode: apply` runs `rotate apply` from a workflow. It belongs in its own
job, after the plan job, behind a GitHub environment with required
reviewers: the plan job writes the plan to its summary, a reviewer reads
it and approves, and only then does the apply job get the write-capable
credentials and run.

### Set up the `rotate-apply` environment

In the repository's Settings, Environments, create an environment named
`rotate-apply` and set:

1. **Required reviewers**: the people who may approve a rotation.
2. **Prevent self-review**: on, so whoever started the run cannot approve
   it.
3. **Deployment branches and tags**: the default branch only, so a
   workflow on another branch cannot use the environment or its secrets.
4. **Environment secrets**: the write-capable operator credentials, which
   only the approved job can read. Keep the plan job's read-only ones as
   repository secrets.

| Provider or consumer | Write-capable credentials for the apply job |
| --- | --- |
| AWS IAM, AWS Secrets Manager | An OIDC role with the `rotate apply` actions in [permissions.md](permissions.md#by-command), via `aws-actions/configure-aws-credentials`. Limit its trust policy to the environment: `"token.actions.githubusercontent.com:sub": "repo:<owner>/<repo>:environment:rotate-apply"`. |
| GitHub Actions secrets | `ROTATE_GITHUB_TOKEN` as an environment secret, with Secrets: read and write on the targets in `rotate.yaml`. |
| GitHub tokens | None to revoke (the credential revocation API needs no token). The replacement is made by hand: see [Manual replacements](#manual-replacements). |
| npm | `ROTATE_NPM_TOKEN` as an environment secret, able to list and delete tokens. An account that asks for a one-time password to delete a token cannot be revoked from a waiting job: rotate exits 1 at the revoke. |
| OpenAI | `OPENAI_ADMIN_KEY` as an environment secret. |

### The caller workflow

```yaml
name: rotate-alert
on:
  workflow_dispatch:
    inputs:
      alert:
        description: Secret-scanning alert number (empty for all open alerts)
        required: false
        type: string

permissions:
  contents: read

jobs:
  plan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write # for the AWS role
    outputs:
      rotation-ids: ${{ steps.rotate.outputs.rotation-ids }}
    steps:
      - uses: actions/checkout@v4 # pin by SHA in your workflow
      - uses: actions/create-github-app-token@v2
        id: app
        with:
          app-id: ${{ vars.ROTATE_APP_ID }}
          private-key: ${{ secrets.ROTATE_APP_KEY }}
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/rotate-plan
          aws-region: us-east-1
      - id: rotate
        uses: smhasan94/rotate@vX.Y.Z # or a full commit SHA
        with:
          alert-number: ${{ inputs.alert }}
          alerts-token: ${{ steps.app.outputs.token }}
          overlap: 15m
        env:
          ROTATE_GITHUB_TOKEN: ${{ secrets.ROTATE_GITHUB_TOKEN }} # read-only
      # The state file ties the rotation ids to the leaked secrets'
      # fingerprints; the apply job confirms by those ids. No secret value.
      - if: steps.rotate.outputs.rotation-ids != ''
        uses: actions/upload-artifact@v4
        with:
          name: rotate-state-${{ github.run_id }}-${{ github.run_attempt }}
          path: ${{ steps.rotate.outputs.state-dir }}
          include-hidden-files: true # the files are under .rotate/
          retention-days: 1
          if-no-files-found: error

  apply:
    needs: plan
    if: needs.plan.outputs.rotation-ids != ''
    runs-on: ubuntu-latest
    environment: rotate-apply # required reviewers, prevent self-review
    timeout-minutes: 60 # longer than overlap; max-wait below it
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/create-github-app-token@v2
        id: app
        with:
          app-id: ${{ vars.ROTATE_APP_ID }}
          private-key: ${{ secrets.ROTATE_APP_KEY }}
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/rotate-apply
          aws-region: us-east-1
      - uses: actions/download-artifact@v4
        with:
          name: rotate-state-${{ github.run_id }}-${{ github.run_attempt }}
          path: ${{ runner.temp }}/rotate-plan-state
      - uses: smhasan94/rotate@vX.Y.Z
        with:
          mode: apply
          alert-number: ${{ inputs.alert }}
          alerts-token: ${{ steps.app.outputs.token }}
          confirm: ${{ needs.plan.outputs.rotation-ids }}
          state-dir: ${{ runner.temp }}/rotate-plan-state
          overlap: 15m
          max-wait: 45m
        env:
          ROTATE_GITHUB_TOKEN: ${{ secrets.ROTATE_GITHUB_TOKEN }} # the environment's, read and write
```

The apply job fetches the alerts again: a new runner has nothing from the
plan job but the state artifact, and the leaked value never travels
between jobs. rotate re-plans from the alerts, finds each secret's planned
rotation in the state file by fingerprint, and runs only the confirmed
ids, without a prompt. The other triggers in [Triggers](#triggers) work
the same way: pass the same `alert-number` expression to both jobs.

### What the apply step does

`rotate apply --stdin --format github-alert --confirm <id> ... --wait`:
create the replacement, update every consumer, verify the replacement,
wait out the overlap window, revoke the old secret. Revoke is always the
last step, and any earlier failure stops before it. A rotation whose
consumers could not all be updated is not revoked unless `force: true`.

The job summary is built from `rotate --json status --all` and the exit
code: one row per confirmed rotation with its step, consumers updated,
revoke time, next step and error. The step's exit code is rotate's, with
one exception: rotate exits 0 with "Nothing to apply." when the alerts it
fetches again plan nothing, for example when an alert was resolved or the
secret revoked while the job waited for approval. The step passes only
when every confirmed rotation is at `revoked` in the state file;
otherwise it exits 2 and names the rotations that were not applied.

| Exit | Meaning | The step | The summary says |
| --- | --- | --- | --- |
| 0 | Every confirmed rotation finished: `rotate status` shows each at `revoked`. | passes | Done. |
| 1 | A step failed; rotate stopped before the revoke. | fails | The old secret is still valid, with each rotation's step and error. |
| 2 | Nothing was changed: a configuration error, an id not in the state file, a manual replacement missing; or rotate exited 0 without applying a confirmed rotation. | fails | rotate's error, or "Not applied" with the rotation ids. |
| 3 | The overlap window is longer than `max-wait`. Created, updated and verified, not revoked. | fails | The time after which the old secret may be revoked. |
| 4 | rotate cannot revoke the old secret. | fails | The provider's instructions for revoking it by hand. |

### The overlap window and the job timeout

A runner cannot come back later, so the step waits out the overlap window
(`--wait`) and then revokes, in the same job. Keep the window short and
below the job's `timeout-minutes` (at most 360 minutes, the default, on
GitHub-hosted runners), and set `max-wait` below the timeout with room
for the rest of the job. Before it fetches anything, the step asks rotate
for the window it will use (`overlap`, else `ROTATE_OVERLAP`, else
`rotate.yaml`). When the window is longer than `max-wait`, the step does
not wait: it creates, updates and verifies, then fails with exit 3 and
the revoke time. After that time, revoke the old secret yourself: with
the state file from the audit artifact (`rotate apply --state-file ...`
with the same input), or by hand at the provider. Resuming a pending
revoke from a later workflow run is not supported. The step also
declines to wait when the state it was given already records a revoke
time for a confirmed rotation that is more than `max-wait` away.

Do not re-run a failed apply job: it would start again from the plan
job's state, not from where the failed run stopped, and could create a
second replacement. The state artifact's name carries
`github.run_attempt` for this reason: "Re-run failed jobs" runs the apply
job as a new attempt whose download finds no artifact of that name, so it
fails before rotate runs; "Re-run all jobs" plans again and hands over a
fresh state. To continue a failed or pending rotation, download the failed
run's audit artifact and use rotate by hand (`rotate status`, `rotate
apply` or `rotate rollback` with `--state-file` and `--audit-log`
pointing into it). With `upload-audit: false` there is no such artifact:
after an exit 3 or 4 no state is left to resume from, and the old secret
must be revoked by hand at the provider.

### The audit artifact

After apply, also when it failed, the Action uploads `.rotate/` of its
state directory (`audit.jsonl` and `state.json`) as the artifact
`rotate-audit-<run id>-<attempt>`, kept 30 days. It holds what the audit
log holds: rotation ids, fingerprints, key ids, consumer references, the
actor and redacted errors, never a secret value ([security.md](security.md)).
Anyone with read access to the repository can download a workflow's
artifacts, so on a public repository set `upload-audit: false`; the job
log and summary are then the record.

### Manual replacements

GitHub tokens, npm tokens and OpenAI keys without an admin key cannot be
created through an API ([providers.md](providers.md)): rotate takes a
replacement you create yourself. In the apply job it comes from an
environment variable named by `replacement-env`. Create the new token,
store it as a secret of the `rotate-apply` environment, apply one
rotation per run, and delete the secret afterwards:

```yaml
      - uses: smhasan94/rotate@vX.Y.Z
        with:
          mode: apply
          confirm: rot-1a2b3c4d # one rotation
          replacement-env: ROTATE_REPLACEMENT
          # ... as above
        env:
          ROTATE_REPLACEMENT: ${{ secrets.ROTATE_REPLACEMENT }}
```

rotate checks that the replacement belongs to the same account as the
leaked secret before it touches any consumer.

## The `repository_dispatch` contract

A webhook receiver (a GitHub App, a serverless function) that wants the
Action to plan an alert as soon as it is created sends:

```http
POST /repos/{owner}/{repo}/dispatches
Authorization: Bearer <token with Contents: write on the repository>
Accept: application/vnd.github+json

{
  "event_type": "secret-scanning-alert",
  "client_payload": { "alert": { "number": 42 } }
}
```

- `event_type` is `secret-scanning-alert`, matching `types:` above.
- `client_payload.alert.number` is the alert number from the webhook's
  `alert.number`. Nothing else is needed: never forward the webhook body,
  and never put a secret in `client_payload` (it has no `secret` field
  anyway, and the payload is visible in the run).
- The dispatch token needs "Contents: write" on the repository. It is the
  receiver's credential, separate from `alerts-token`.
- `client_payload` holds at most 10 top-level properties and 64 KB.
- Useful webhook actions to forward: `created`, `reopened`,
  `publicly_leaked` and `validated`.

The caller workflow passes the number on as
`github.event.client_payload.alert.number`; the Action checks it is digits
and commas before using it.

## Limits

- Apply waits out the overlap window in the job; a pending revoke is not
  resumed by a later workflow run.
- 100 alerts per poll, no pagination.
- No pull request or issue comment: the summary links the alerts and the
  run.
- Linux and macOS runners (x86_64 and aarch64). Self-hosted runners need
  `bash`, `curl`, `jq`, `tar` and `sha256sum` or `shasum`, all present on
  GitHub-hosted runners.
- No marketplace listing yet.
