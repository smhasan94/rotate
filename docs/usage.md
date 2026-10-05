# Using rotate

A guide to follow during an incident: a scanner or a GitHub secret-scanning
alert has found a leaked credential, and you need to replace it everywhere
it is used and then kill the old one, without an outage.

rotate works in four commands:

- `rotate plan` (the default) shows what would happen and changes nothing.
- `rotate apply` does it: create the replacement, update every consumer,
  verify the replacement, revoke the old secret.
- `rotate status` shows rotations that are in progress or waiting.
- `rotate rollback` undoes a rotation.

Related pages: [config.md](config.md) (every `rotate.yaml` field),
[non-interactive.md](non-interactive.md) (scripts and CI),
[security.md](security.md) (what rotate guarantees and what it does not),
[providers.md](providers.md) (what is automated, manual or unsupported per
provider) and [permissions.md](permissions.md) (the operator credentials
each provider needs).

The command blocks marked as tested in this page's source run in CI
(`tests/user_docs.rs`) against the acceptance-test models of AWS and GitHub,
so the commands, exit codes and quoted output below are what rotate really
does.

## 1. Install

Prebuilt Linux and macOS binaries (x86_64 and aarch64) are attached to each
[GitHub Release](https://github.com/smhasan94/rotate/releases) with a
`SHA256SUMS` file. The [README](../README.md#install) has a copy-paste block
that downloads the one for your machine, checks its checksum and installs it.

Or build from source with Rust stable 1.94.1 or newer:

```sh
cargo install --git https://github.com/smhasan94/rotate --tag v0.2.0 --locked
rotate --version
rotate --help
```

`rotate --help` and `rotate <command> --help` (or `-h` for a summary) list
every flag. `rotate --version` (`-V`) prints the version.

## 2. Before the first run

rotate never uses the leaked secret as its own credential. It acts with
your credentials (the "operator" credentials), read from the environment:

| Provider or consumer | Operator credential |
| --- | --- |
| AWS IAM keys, AWS Secrets Manager | The standard AWS credential chain (`AWS_PROFILE`, `AWS_ACCESS_KEY_ID`, SSO, ...) and region (`AWS_REGION` or `providers.aws.region`). |
| GitHub Actions secrets | A token in `ROTATE_GITHUB_TOKEN` (or `GITHUB_TOKEN`). |
| npm tokens | An `npm login` session token in `ROTATE_NPM_TOKEN` (or `NPM_TOKEN`). |
| OpenAI keys | An Admin API key in `OPENAI_ADMIN_KEY` (or the variable `providers.openai.admin_key_env` names). |

[permissions.md](permissions.md) has the minimal IAM policy and the token
scopes. [providers.md](providers.md) says what rotate does without each
credential.

Then tell rotate where your secrets are used. rotate searches only the
consumers listed in `rotate.yaml` in the working directory (or the file
`--config` or `ROTATE_CONFIG` names). This example says that the GitHub
Actions secrets of `acme/api` and the Secrets Manager entry `prod/app` may
hold leaked secrets:

<!-- test: rotate.yaml -->
```yaml
consumers:
  github_actions:
    targets: [acme/api]
  aws_secrets_manager:
    secrets: [prod/app]
providers:
  aws:
    region: us-east-1
```

Actions secrets are matched by name: by default `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY` for an AWS key, `GH_TOKEN` or `GH_PAT` for a
GitHub token, `NPM_TOKEN` for an npm token and
`OPENAI_API_KEY` for an OpenAI key. Secrets Manager entries are matched by
value. [config.md](config.md) lists every field, the name conventions and
how to add your own names.

rotate keeps its own files in `./.rotate/`: the state file
(`.rotate/state.json`) and the audit log (`.rotate/audit.jsonl`). Run every
command for one incident from the same directory, or point `--state-file`
and `--audit-log` at the same files each time.

## 3. First run: plan

Give `rotate plan` the scanner's report. It reads TruffleHog (`trufflehog
... --json`, one JSON object per line) and gitleaks (`gitleaks ... -f json`)
reports and detects which one it is; `--format trufflehog` or `--format
gitleaks` forces it. [report-formats.md](report-formats.md) lists the fields
it reads.

<!-- test: first-run -->
```sh
rotate plan trufflehog-report.json
# exit: 0
# expect: Plan: 1 to rotate, 0 skipped. Dry run: nothing was changed.
# expect: deactivate the access key (not deleted; rollback can reactivate it)
```

`rotate` with no command is the same as `rotate plan`.

For a single secret, for example one pasted from a GitHub alert, use
`--stdin` and paste it, then press Ctrl-D. Never pass a secret as an
argument: it would end up in your shell history. An AWS key pair is given as
`KEY_ID:SECRET` or on two lines. `--provider aws` (or `github`, `npm`,
`openai`) skips identification.

```sh
pbpaste | rotate plan --stdin
```

The plan for the report above looks like this:

```text
Plan: 1 to rotate, 0 skipped. Dry run: nothing was changed.

Rotation rot-5f36d3cd  aws  sha256:8088a3c392bc0b3e
  identity:     arn:aws:iam::000000000000:user/deploy-bot
  sources:      deploy/ci.env:2@4b1d2c3e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c
  replacement:  create a new aws credential for arn:aws:iam::000000000000:user/deploy-bot
  consumers:
    github-actions       github-actions:acme/api:AWS_ACCESS_KEY_ID                                 by name   update
    github-actions       github-actions:acme/api:AWS_SECRET_ACCESS_KEY                             by name   update
    aws-secrets-manager  aws-secrets-manager:prod/app#$.AWS_SECRET_ACCESS_KEY|$.AWS_ACCESS_KEY_ID  by value  update
  revoke:       deactivate the access key (not deleted; rollback can reactivate it)
  overlap:      0s
```

### Reading the plan

- **Rotation id** (`rot-` and 8 hex characters): what you type to confirm
  apply. It is recorded in the state file and stays the same on every later
  `plan` or `apply` in the same directory (a rolled-back rotation gets a
  new id next time).
- **Fingerprint** (`sha256:` and 16 hex characters): how rotate names a
  secret everywhere instead of printing it. See [security.md](security.md).
- **identity** and **sources**: who owns the secret, and where the scanner
  found it (`file:line@commit`).
- **replacement**: what apply creates, or `manual` when you will create it
  yourself and paste it (GitHub and npm tokens, and OpenAI keys unless an
  admin key and `allow_broader_replacement` are both set).
- **consumers**: every place found holding the secret, how it was matched
  (`by name` or `by value`) and whether apply can update it.
- **revoke**: what happens to the old secret at the end.
- **overlap**: how long the old secret stays valid after consumers are
  updated (section 5).
- **warning** and **blockers**: anything that would make apply refuse to
  revoke, such as a consumer it cannot update, a revoke that has to be done
  by hand, or an IAM user that already has two keys.
- **Skipped**: secrets that are invalid, unsupported, unknown or already
  rotated, with the reason. Nothing happens to them.

Right under the header, a `warning:` line names each endpoint in
`rotate.yaml` that differs from its default, such as
`providers.npm.registry is https://npm.example.com (default
https://registry.npmjs.org)`. Check it is a server you trust: new secrets
and your operator credentials go there. See
[config.md](config.md#endpoint-urls).

`plan` exits 0 even when it lists blockers. Its only write is local: each
new rotation is recorded at step `planned` in the state file.

More plan flags:

- `--check-permissions` also probes, read-only, whether your own operator
  credentials can do what apply will need, and adds what is missing as
  blockers. See [permissions.md](permissions.md).
- `--concurrency N` (1 to 64, default 8): how many provider checks run at
  once for a large report.
- `--json` prints the plan as one JSON document
  ([plan-schema.json](plan-schema.json)); see
  [non-interactive.md](non-interactive.md).

## 4. Apply

`rotate apply` takes the same input, builds the same plan, prints it, and
asks you to type each rotation id. The id is read from the terminal, never
from stdin, so `--stdin` works too.

```sh
rotate apply trufflehog-report.json
# Type the rotation id rot-5f36d3cd to continue: rot-5f36d3cd
```

`--all` asks once for every rotation in the plan: type `all`.
`--confirm <rotation-id>` (repeatable) confirms without a prompt, for
scripts:

<!-- test: first-run -->
```sh
rotate apply trufflehog-report.json --confirm rot-5f36d3cd
# exit: 0
# expect: Apply: 1 revoked, 0 pending revoke, 0 held, 0 failed, 0 need rollback, 0 revoke by hand, 0 skipped.
```

Every confirmed rotation is taken through these steps, in this order:

1. **create** the replacement (or, in manual mode, ask you to paste it);
2. **update** every consumer the plan listed;
3. **verify** that the replacement works and belongs to the same owner;
4. **revoke** the old secret, last. An npm account that asks for a
   one-time password to delete tokens gets a hidden prompt here (or
   `ROTATE_NPM_OTP`); see [permissions.md](permissions.md).

apply takes every rotation through create, update, verify and the revoke
gate first, then revokes the old secrets, last of all. GitHub tokens go to
GitHub's credential revocation API together, in one request per 1000
tokens (GitHub allows 60 such requests an hour), and apply says so on
stderr. If GitHub rate-limits a request, the rotations still to revoke fail
at revoke with the old secret still valid and the time to re-run apply;
nothing is retried. Every rotation keeps its own audit entry and state.

State is saved after every step and every step is appended to the audit
log. If any step before revoke fails, that rotation stops, the old secret is
not revoked and keeps working, and apply exits 1; the summary says where
every consumer stands. Other rotations in the same run still go ahead.

A consumer that could not be updated holds the revoke (outcome `held`, exit
1). Fix it and re-run, or pass `--force` to revoke anyway. `--force` is
recorded in the state file and the audit log with your name; it never skips
a failed create or verify.

### Manual replacement

When the provider's API cannot create the replacement, apply prints what to
create (for a GitHub token, the scopes to give it) and asks you to paste it
with terminal echo off. It is accepted only once the provider confirms it
belongs to the same account as the leaked one; a wrong paste is asked for
again, up to three times. Without a terminal, `--replacement-from-env <VAR>`
or `--replacement-file <PATH>` supply it; see
[non-interactive.md](non-interactive.md).

### Revoke by hand

When rotate cannot revoke the old secret itself (an OpenAI key without an
admin key, a GitHub App installation token, a legacy-format GitHub token),
apply updates the consumers, verifies the replacement, then stops at step
`revoke_manual`, prints the provider's instructions and exits 4. Delete the
old secret as told, then run the same `rotate apply` again: it checks,
read-only, that the old secret no longer works and records the rotation
revoked.

### Re-running

Re-running `rotate apply` with the same input is safe. It resumes each
rotation where it stopped and never repeats a state-changing step. A secret
whose rotation finished is listed as already rotated and nothing is called
for it:

<!-- test: first-run -->
```sh
rotate status
# exit: 0
# expect: no rotations in progress (1 finished; use --all to show them)
rotate status --all
# exit: 0
# expect: revoked
rotate plan trufflehog-report.json
# exit: 0
# expect: Plan: 0 to rotate, 1 skipped. Dry run: nothing was changed.
# expect: already rotated
```

One case cannot be resumed: a run that stopped after the replacement was
created but before every consumer held it. rotate never stores the
replacement's value, so a new process cannot finish writing it. apply marks
the rotation `needs_rollback`; run `rotate rollback` with the same input,
then apply again.

## 5. Overlap window

By default the old secret is revoked as soon as the replacement is
verified (overlap `0s`): a leaked key should die fast. When consumers need
time to pick up the new value (a deploy, a cache), set an overlap window
with `--overlap`, `ROTATE_OVERLAP` or `overlap_window` in `rotate.yaml`. It
is one or more `<number><s|m|h|d>` groups: `30m`, `1h30m`, `7d`.

With a window, apply updates and verifies, records the revoke as pending
with its earliest time, and exits 3:

<!-- test: overlap -->
```sh
rotate apply trufflehog-report.json --confirm rot-5f36d3cd --overlap 1h
# exit: 3
# expect: Apply: 0 revoked, 1 pending revoke
# expect: re-run rotate apply after that time to revoke it
```

`rotate status` shows the pending revoke and when to re-run, and also exits
3:

<!-- test: overlap -->
```sh
rotate status
# exit: 3
# expect: pending_revoke
# expect: to revoke the old secret
```

Re-run the same apply after that time to revoke the old secret. Before
then a re-run makes no state-changing call and exits 3 again. The recorded
time is kept: a different `--overlap` on the re-run does not move it. The
re-run's plan shows that time and what is left of it on the `overlap:`
row, and lists every consumer the first run recorded, marked
`(recorded)`, including one matched by value that now holds the
replacement.

<!-- test: overlap -->
```sh
rotate apply trufflehog-report.json --confirm rot-5f36d3cd
# exit: 3
# expect: 1 pending revoke
# expect: recorded by an earlier run
# expect: updated (recorded)
```

For a short window, `--wait` waits in the same run and then revokes. If it
is interrupted, the revoke stays pending and a later apply finishes it.
With several rotations, apply waits once per provider, until the latest
time among that provider's rotations, then revokes them together.

<!-- test: wait -->
```sh
rotate apply trufflehog-report.json --confirm rot-5f36d3cd --overlap 5s --wait
# exit: 0
# expect: Apply: 1 revoked
```

## 6. Rollback

`rotate rollback` undoes a rotation: it reactivates the old secret where
the provider can (an AWS key is reactivated), puts the old value back in
every consumer apply updated, and revokes the replacement. rotate never
stores the old value, so give it the same report or `--stdin` secret again;
it is matched to the state file by fingerprint. It prints its plan and asks
for the rotation id; `--confirm <rotation-id>` skips the prompt, and
`--rotation <rotation-id>` picks one rotation when the input matches
several.

Continuing the overlap example, while the revoke is still pending:

<!-- test: overlap -->
```sh
rotate rollback trufflehog-report.json --confirm rot-5f36d3cd
# exit: 0
# expect: Rollback: 1 rolled back, 0 with the old secret still revoked, 0 failed.
rotate status --all
# exit: 0
# expect: rolled_back
```

- A secret that matches no rotation exits 2 and nothing is called.
- When the provider cannot bring the old secret back (GitHub, npm and
  OpenAI never can; nor can any provider after a revoke by hand),
  consumers are still restored and the replacement is revoked, but the
  restored consumers now hold a revoked secret. The plan says so before you
  confirm, the summary counts it as "with the old secret still revoked" and
  names those consumers, and rollback exits 1, also when an interrupted
  rollback is finished by a re-run. Create a new credential and run
  `rotate apply` again. A pasted (manual) replacement has to be revoked by
  hand.
- Any error stops the rollback before the replacement is revoked and exits
  1; re-running continues where it stopped.
- AWS deactivates the replacement key and never deletes it, and an IAM user
  can hold two keys. Delete the inactive replacement key yourself before
  you apply again, or the next plan warns that no replacement can be
  created.

## 7. Status

`rotate status` lists rotations that are in progress or waiting. It reads
the state file and the audit log only: no network call, no write, no lock.
Each row has the rotation id, provider, fingerprint, step, time since the
last update, consumers updated, the revoke time for a pending revoke, and a
hint saying what to do next. A rotation whose last step failed gets a
`last error` line under its row; a pending revoke is waiting, not failing,
so it has only its hint. `--all` also lists finished rotations
(`revoked`, `rolled_back`). `--json` prints the rows as JSON
([status-schema.json](status-schema.json)).

It exits 3 when any rotation is pending (`created`, `consumers_updated`,
`verified`, `pending_revoke`, `failed`, `needs_rollback`, `revoke_manual`,
or being rolled back) and 0 otherwise, including when there is no state
file. `planned` rotations are listed but are not pending.

## 8. Flags

Global flags work before or after the command.

| Flag | Commands | Meaning |
| --- | --- | --- |
| `--config <PATH>` | all | `rotate.yaml` to read (env `ROTATE_CONFIG`). Default `./rotate.yaml` when present. |
| `--json` | plan, status | Machine-readable output. `apply` and `rollback` refuse it (exit 2). |
| `-v`, `--verbose` | all | More log detail on stderr; repeat up to `-vvv`. Logs are redacted like all output. |
| `--audit-log <PATH>` | all | Audit log path (env `ROTATE_AUDIT_LOG`). |
| `--state-file <PATH>` | all | State file path (env `ROTATE_STATE_FILE`). |
| `--overlap <DURATION>` | all | Overlap window (env `ROTATE_OVERLAP`); used by `apply`. |
| `-h`, `--help` | all | Help. |
| `-V`, `--version` | none | Version. |
| `REPORT` | plan, apply, rollback | The scanner report to read. |
| `--format <FORMAT>` | plan, apply, rollback | `trufflehog` or `gitleaks`; detected when omitted. |
| `--stdin` | plan, apply, rollback | Read one secret from stdin instead of a report. |
| `--provider <NAME>` | plan, apply, rollback | Provider of the `--stdin` secret: `aws`, `github`, `npm` or `openai`. |
| `--concurrency <N>` | plan, apply, rollback | Provider checks in flight at once, 1 to 64. Default 8. |
| `--check-permissions` | plan | Probe the operator's permissions, read-only. |
| `--allow-broader-replacement` | plan, apply | Let rotate create an OpenAI replacement with all permissions (see [config.md](config.md#providersopenaiallow_broader_replacement)). |
| `--confirm <ROTATION_ID>` | apply, rollback | Confirm this rotation without a prompt. Repeatable. |
| `--all` | apply | Confirm every rotation with one prompt. |
| `--all` | status | Also list finished rotations. |
| `--replacement-from-env <VAR>` | apply | Manual mode: read the replacement from this environment variable. |
| `--replacement-file <PATH>` | apply | Manual mode: read the replacement from this file (mode 600). |
| `--force` | apply | Revoke even if some consumers could not be updated. |
| `--wait` | apply | Wait out the overlap window in this run, then revoke. |
| `--rotation <ROTATION_ID>` | rollback | Roll back only this rotation. |

## 9. Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Everything requested was done. `plan` exits 0 even when it lists blockers. |
| 1 | A rotation step failed. The old secret is still valid unless the output says otherwise. Also `rollback` that finished with the old secret still revoked: the restored consumers hold a revoked secret. |
| 2 | Bad arguments, bad configuration, a wrong or unknown rotation id, a state file held by another rotate process, or a rollback input that matches no rotation. Nothing was changed. |
| 3 | Work is pending: `apply` recorded a revoke waiting for its overlap window, or `status` found a rotation that is pending, failed, needs rollback or waits for a revoke by hand. |
| 4 | `apply`: the replacement is live and verified, but rotate cannot revoke the old secret; delete it by hand as the summary says, then re-run `apply` to record it. |
| 101 | rotate panicked. This is a bug; the message is redacted like all other output. |

When one `apply` run ends rotations differently, the exit code is the most
urgent: 1 wins over 4, 4 over 3, and 3 over 2.
