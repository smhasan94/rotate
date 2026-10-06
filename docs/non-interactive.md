# Non-interactive use

How to run rotate from scripts and CI, where nobody can type at a prompt.
The interactive flow is in [usage.md](usage.md); this page covers the flags
and exit codes a script relies on, and ends with a GitHub Actions workflow
that runs `rotate plan` on a schedule.

## Rules for scripts

- `rotate plan` never prompts and never changes anything remote. It is
  always safe to run unattended.
- `rotate apply` and `rotate rollback` never act without a confirmation.
  Without a terminal there is no prompt to answer, so confirm each rotation
  by id with `--confirm`. A confirmation prompt that cannot be answered
  exits 2 having changed nothing.
- Secrets are never passed as arguments. Use a report file, `--stdin`, or
  for a manual replacement `--replacement-from-env` or `--replacement-file`.
- Output for programs goes to stdout (the plan, the status rows, the
  summary). Warnings, notes, questions and logs (`-v`) go to stderr. Both
  are redacted.

## Confirming: `--confirm` and `--all`

`--confirm <ROTATION_ID>` confirms one rotation from the plan; repeat it for
more. Only the rotations named run; the others in the plan are left alone.
An id that is not in the plan exits 2 having changed nothing, and the error
lists the ids that are.

The rotation id comes from the plan. It is stored in the state file, so it
stays the same between `plan` and `apply` when both run in the same
directory (or with the same `--state-file`):

```sh
id=$(rotate --json plan trufflehog-report.json | jq -r '.rotations[0].rotation_id')
rotate apply trufflehog-report.json --confirm "$id"
```

`rotate rollback` takes `--confirm` the same way, and `--rotation <ID>` to
pick one rotation when the input matches several.

`--all` (apply only) confirms every rotation with a single prompt where you
type `all`. It still needs a terminal; in CI use `--confirm`.

## Manual replacements: `--replacement-from-env` and `--replacement-file`

Providers whose API cannot create a replacement (GitHub and npm tokens,
OpenAI keys without an admin key; see [providers.md](providers.md)) ask for
the new secret at a hidden prompt. In a script, create the new token first
and pass it in one of two ways:

- `--replacement-from-env <VAR>`: the name of an environment variable that
  holds it (the name, never the value);
- `--replacement-file <PATH>`: a file that holds it. The file must be a
  regular file readable by its owner only (`chmod 600`), or apply refuses
  it.

```sh
NEW_TOKEN="$(cat /run/secrets/new-token)" \
  rotate apply --stdin --confirm rot-5f36d3cd --replacement-from-env NEW_TOKEN < leaked-token
```

Either flag supplies one value for one rotation, with one attempt:

- With more than one confirmed manual rotation, apply exits 2 having
  changed nothing; confirm them one at a time.
- With no manual rotation confirmed, the value is not used and a note says
  so.
- A value that does not belong to the same account as the leaked secret
  fails the rotation before any consumer is touched (exit 1).

The value is read before anything else happens, never printed and never
stored; the state file records `replacement_ref: manual` and its
fingerprint.

## Machine-readable output: `--json`

`--json` is a global flag, accepted before or after the command.

| Command | `--json` output |
| --- | --- |
| `rotate plan` | One JSON document described by [plan-schema.json](plan-schema.json): `version`, `overlap_window`, `rotations` (each with `rotation_id`, `provider`, `fingerprint`, `consumers`, `blockers`, ...), `skipped` and `warnings` (one per non-default endpoint in `rotate.yaml`). |
| `rotate status` | An array of rows described by [status-schema.json](status-schema.json). |
| `rotate apply`, `rotate rollback` | Not supported yet: exits 2 with "does not support --json yet". Use the exit code and the state file. |

For example, to fail a job when any secret in a report still needs
rotating:

```sh
rotate --json plan trufflehog-report.json > plan.json
jq -e '.rotations | length == 0' plan.json
```

A report can also come on stdin with `--format`, so a GitHub
secret-scanning alert goes from the REST API to rotate without the value
touching a variable or a file. The token must be able to read
secret-scanning alerts; a workflow's `GITHUB_TOKEN` cannot (see
[report-formats.md](report-formats.md#github-secret-scanning-alerts)):

```sh
gh api "repos/$REPO/secret-scanning/alerts/$ALERT" \
  | rotate --json plan --stdin --format github-alert > plan.json
```

The GitHub Action in this repository does exactly that, polls the open
alerts when given no number, and writes the plan to the job summary:
[github-action.md](github-action.md).

## Other flags a script uses

- `--force` (apply): revoke even if some consumers could not be updated.
  Recorded in the audit log with the actor. Never skips a failed create or
  verify.
- `--wait` (apply): wait out the overlap window in the same run instead of
  exiting 3. Mind your CI job's timeout.
- `--overlap <DURATION>`: the overlap window for this run (also
  `ROTATE_OVERLAP`).
- `--config`, `--state-file`, `--audit-log`: where rotate reads its config
  and keeps its files (also `ROTATE_CONFIG`, `ROTATE_STATE_FILE`,
  `ROTATE_AUDIT_LOG`). Keep the state file between runs of one incident:
  resume, `status` and `rollback` need it.
- `--stdin`, `--provider`, `--format`, `--concurrency`,
  `--check-permissions`, `--verbose`: as in [usage.md](usage.md#8-flags).
- `ROTATE_NPM_OTP`: a one-time password for an npm account that asks for
  one to delete a token. It serves one delete and is valid about 30
  seconds, so mint it moments before the run; it only fits a run that
  revokes at once (no overlap window, or the re-run after it), not
  `--wait`. Without it a run with no terminal fails at revoke, naming the
  page to delete the token on.

Set `ROTATE_ACTOR` so the audit log says which job acted, for example
`ROTATE_ACTOR=github-actions/acme/api/run-1234`. Without it the actor is
`user@hostname` of the runner.

## Exit codes

| Code | Meaning | What a script should do |
| --- | --- | --- |
| 0 | Everything requested was done. `plan` exits 0 even when it lists blockers. | Continue. |
| 1 | A rotation step failed. The old secret is still valid unless the output says otherwise. Also `rollback` that finished with the old secret still revoked, so the restored consumers hold a revoked secret. A revoke the provider rate-limited (GitHub allows 60 revocation requests an hour) also exits 1, naming when to re-run. | Stop and page a human; run `rotate status --all`. After such a rollback, create a new credential and run `rotate apply`. After a rate-limited revoke, re-run the same `rotate apply` after the time it printed. |
| 2 | Bad arguments or configuration, an unknown rotation id, an unanswerable prompt, a state file held by another rotate process, `--json` on apply or rollback, or a rollback input that matches no rotation. Nothing was changed. | Fix the invocation. |
| 3 | Work is pending: `apply` recorded a revoke waiting for its overlap window, or `status` found a rotation that is pending, failed, needs rollback or waits for a revoke by hand. | Re-run the same `rotate apply` after the time it printed, or schedule it. |
| 4 | `apply`: the replacement is live and verified, but rotate cannot revoke the old secret. | A human deletes the old secret as the summary says, then re-runs `rotate apply`. |
| 101 | rotate panicked (a bug). | Stop; report it. |

When one `apply` run ends rotations differently, the most urgent code wins:
1 over 4, 4 over 3, 3 over 2.

```sh
set +e
rotate apply trufflehog-report.json --confirm "$id"
code=$?
set -e
case "$code" in
  0) echo "rotated" ;;
  3) echo "revoke pending; re-run rotate apply later" ;;
  4) echo "delete the old secret by hand, then re-run rotate apply" ;;
  *) exit "$code" ;;
esac
```

## Example: scheduled `rotate plan` in GitHub Actions

This workflow scans the repository with TruffleHog every morning and runs
`rotate plan` on the result. It fails when a verified secret in the history
is still valid, and uploads the plan (fingerprints only, no values) for the
on-call engineer, who then runs `rotate apply` by hand. It changes nothing:
`plan` makes no state-changing call.

```yaml
name: leaked-secrets
on:
  schedule:
    - cron: "17 6 * * *"
  workflow_dispatch:

permissions:
  contents: read
  id-token: write # for the AWS role below

jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Scan the history with TruffleHog
        run: |
          docker run --rm -v "$PWD:/repo" trufflesecurity/trufflehog:latest \
            git file:///repo --json --only-verified > "$RUNNER_TEMP/trufflehog-report.json"

      # Read-only operator credentials: plan only reads. permissions.md has
      # the actions; with --check-permissions add iam:SimulatePrincipalPolicy.
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/rotate-plan
          aws-region: us-east-1

      - name: Install rotate
        run: cargo install --git https://github.com/smhasan94/rotate --locked

      - name: rotate plan
        env:
          # Reads the Actions secrets listed in rotate.yaml.
          ROTATE_GITHUB_TOKEN: ${{ secrets.ROTATE_GITHUB_TOKEN }}
          ROTATE_ACTOR: github-actions/${{ github.repository }}/${{ github.run_id }}
        run: |
          rotate --json plan "$RUNNER_TEMP/trufflehog-report.json" > plan.json
          rotate plan "$RUNNER_TEMP/trufflehog-report.json"
          rm -f "$RUNNER_TEMP/trufflehog-report.json"
          jq -e '.rotations | length == 0' plan.json

      - name: Upload the plan
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: rotate-plan
          path: plan.json
```

Notes:

- The report holds the leaked secrets in plain text. Keep it out of the
  workspace and artifacts, and delete it when done, as above.
- `rotate.yaml` in the repository root names the consumers to search; see
  [config.md](config.md).
- The runner's `.rotate/` directory is thrown away after the job. That is
  fine for `plan`. A job that runs `apply` must keep the state file (for
  example as a protected artifact or on a persistent runner) so that a
  pending revoke, a resume or a rollback can find it.
- Prebuilt binaries will be attached to GitHub Releases from the first
  tagged version; download one instead of building with `cargo install`
  once they exist.
