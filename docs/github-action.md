# GitHub Action: plan a secret-scanning alert

rotate ships a composite GitHub Action, `action.yml` at the root of this
repository. Given a secret-scanning alert number, or none, it fetches the
alerts with GitHub's REST API, pipes them into
`rotate plan --stdin --format github-alert`, and writes the plan to the job
summary: what would be created, updated and revoked for each leaked secret,
and why anything was skipped.

It changes nothing. The Action only runs `rotate plan`, which makes no
state-changing call to any provider or consumer, and it only sends GET
requests to the GitHub API. Applying the plan from a workflow, behind an
environment approval, is planned (SHA-338); until then, run `rotate apply`
by hand from the plan.

What it does not do: it does not host a webhook receiver, comment on pull
requests or issues, page through more than 100 alerts, or run on Windows
runners.

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
| `mode` | `plan` | `plan`, the only mode for now. `apply` is refused (SHA-338). |
| `verbose` | `0` | rotate's log verbosity, `0` to `3` (`-v` to `-vvv`). Logs are redacted at every level. |

Inputs reach the scripts through environment variables, never through
`run:` text, so a hostile `client_payload` cannot inject shell. They are
checked before anything is downloaded or fetched: an `alert-number` that is
not digits and commas, a `repository` that is not `owner/repo`, an empty
`alerts-token` or `mode: apply` fails the step with exit code 2 and one
line naming the input.

## Outputs

| Output | Description |
| --- | --- |
| `rotation-ids` | Comma-separated rotation ids from the plan, such as `rot-1a2b3c4d,rot-5e6f7a8b`; empty when there is nothing to rotate. |
| `plan-path` | Path of `plan.json`, the `rotate plan --json` output ([plan-schema.json](plan-schema.json)). Holds fingerprints and references only. |
| `summary-path` | Path of the Markdown the Action appended to the job summary. |
| `state-dir` | Directory holding `.rotate/state.json` and `.rotate/audit.jsonl` for this run, under `RUNNER_TEMP`. |
| `exit-code` | rotate's exit code, or the Action's own when rotate did not run (`1` when the alerts could not be fetched). |

Everything lives under `$RUNNER_TEMP/rotate/`, readable by the runner's
user only, and is discarded with the runner. Upload `plan-path` or
`state-dir` as an artifact if a later job needs them; they hold no secret
value but name your consumers and key ids, so keep the retention short on
a public repository.

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

- Plan only. Apply behind an approval is SHA-338.
- 100 alerts per poll, no pagination.
- No pull request or issue comment: the summary links the alerts and the
  run.
- Linux and macOS runners (x86_64 and aarch64). Self-hosted runners need
  `bash`, `curl`, `jq`, `tar` and `sha256sum` or `shasum`, all present on
  GitHub-hosted runners.
- No marketplace listing yet.
