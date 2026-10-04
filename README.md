# rotate

[![ci](https://github.com/smhasan94/rotate/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/smhasan94/rotate/actions/workflows/ci.yml)

rotate is an open-source CLI that revokes and rotates leaked secrets safely,
end to end. Give it a TruffleHog or gitleaks report, or a single secret on
stdin. It works out which provider each secret belongs to and whether it is
still valid, creates a replacement, updates every place that uses the secret
(GitHub Actions secrets, AWS Secrets Manager), checks that the new secret
works, and only then revokes the old one. Every step goes to a local audit
log that holds fingerprints, never values.

MVP providers: AWS IAM access keys, GitHub tokens, npm access tokens and
OpenAI API keys.

## Status

Pre-release. Nothing is published yet, and the tool cannot rotate anything
today.

What works now:

- `rotate plan` reads a TruffleHog (`--json`) or gitleaks (`-f json`) report,
  or one secret with `--stdin`. It dedupes the findings by fingerprint,
  identifies the provider, checks validity with bounded concurrency
  (`--concurrency N`, default 8), and asks every consumer where each valid
  secret is used. For each secret it prints the plan: the replacement to
  create (or "manual" when you will paste it), the consumers to update and
  any that cannot be, the revoke action, the overlap window, and blockers
  that would make `rotate apply` refuse to revoke without `--force`. Invalid,
  unsupported and unknown secrets are listed as skipped with the reason.
  `--json` prints the same plan as one document described by
  [docs/plan-schema.json](docs/plan-schema.json).
- `rotate plan` is a dry run: it makes no state-changing API call. Its one
  write is local: each new rotation is recorded at step `planned` in
  `.rotate/state.json` with a short id (`rot-` and 8 hex characters) that
  stays the same on the next `plan` run. It exits 0 even when blockers
  exist, and 2 if another rotate process holds the state file.
- `rotate apply` runs the same plan, prints it, and asks you to type each
  rotation id (read from the terminal, never stdin, so `--stdin` still
  works). `--confirm <rotation-id>` (repeatable) replaces the prompt for
  scripts and CI, and `--all` confirms every rotation with one prompt where
  you type `all`. A wrong or unknown id exits 2 having changed nothing.
  For each confirmed rotation it creates the replacement, updates every
  consumer, verifies the replacement belongs to the same owner, and only
  then revokes the old secret. State is saved after every step and every
  step is appended to `.rotate/audit.jsonl`. Any failure before the revoke
  stops that rotation, marks it `failed` with the step that failed, never
  revokes, and exits 1; the summary says the old secret is still valid and
  where every consumer stands (`updated`, `failed`, `skipped`,
  `unchanged`). Other rotations in the run still go ahead. A consumer that
  could not be updated (not updatable, or its update failed) holds the
  revoke at `verified` and exits 1; re-run with `--force` to revoke anyway.
  `--force` is recorded in the state file (`force: true`) and as one
  `force` audit entry per consumer revoked past, with the actor, before the
  revoke. It never skips a failed create or verify. If the revoke itself
  fails, the summary says the replacement is live and the old secret may
  still be valid. With an overlap window above 0 (`--overlap`, `overlap_window`
  in `rotate.yaml`, default 0) the revoke is recorded as pending with its
  earliest time (`revoke_not_before`) and apply exits 3, saying when to
  re-run. `--wait` instead sleeps until then and revokes in the same run.
- Re-running `rotate apply` with the same input is idempotent and resumes
  where the last run stopped, never repeating a state-changing step: a
  pending revoke is completed once its time has passed (before then the
  re-run makes no state-changing call and exits 3 with the time left; a
  different `--overlap` does not move a recorded time); a run killed after
  updating consumers resumes at verify, checking the replacement by its
  provider reference (AWS: the new key is Active and belongs to the same
  IAM user; a provider that cannot check by reference, such as GitHub, or a
  pasted replacement leaves it `needs_rollback`); a run stopped by a failed
  verify or revoke continues from that step, and one whose create failed
  starts over. Steps not repeated are audited with outcome `skipped`. A rotation
  stopped after the replacement was created but before every consumer held
  it cannot be resumed by a new process, because rotate never stores the
  replacement's value: apply marks it `needs_rollback`, updates nothing,
  and tells you to run `rotate rollback` with the same input, then apply
  again. A secret whose rotation finished is listed by `plan` and `apply`
  as "already rotated on <date>" and no call is made for it.
- Manual replacement mode, for providers whose API cannot mint a
  replacement (GitHub and npm tokens, and OpenAI keys without an Admin API
  key). Apply prints what to create, then
  asks you to paste the new secret with terminal echo turned off. It is
  accepted only once the provider confirms it belongs to the same account
  as the leaked one; a wrong paste is asked for again, up to three times,
  and then the rotation fails before any consumer is touched. For scripts,
  `--replacement-from-env <VAR>` or `--replacement-file <PATH>` (a file
  readable by its owner only, `chmod 600`) supply the value instead, for
  one rotation and one attempt. The value is never printed or stored; the
  state file records `replacement_ref: manual` and its fingerprint.
- `rotate rollback` undoes a rotation. rotate never stores the old value,
  so pass the same report or `--stdin` secret again; it is matched to the
  rotations in `.rotate/state.json` by fingerprint (`--rotation <id>` picks
  one). A secret that matches no rotation exits 2 with "no rotation found
  for fingerprint" having made no call. Rollback prints its plan and asks
  for the rotation id (or takes `--confirm <id>`), then, in this order:
  reactivates the old secret where the provider can (AWS reactivates the
  deactivated key), restores the old value in every consumer apply
  updated (consumers whose update failed or was skipped are left alone),
  and revokes the replacement. If the provider cannot reactivate the old
  secret, consumers are still restored and a warning says the old secret
  stays revoked; a pasted (manual) replacement has to be revoked by hand.
  Any error stops the rollback at that step, before the replacement is
  revoked, and exits 1; re-running continues from where it stopped without
  repeating a step, and a finished rollback (`rolled_back`) makes no call.
  Every action is saved to the state file and appended to the audit log
  with step `rollback`. Rolling back without the state file written by
  apply is not supported.
- `rotate status` shows what is in progress without touching any provider:
  it reads `.rotate/state.json` (without taking its lock) and
  `.rotate/audit.jsonl`, makes no network call and writes nothing. Each row
  has the rotation id, provider, fingerprint, step, time since the last
  update, consumers updated out of all recorded, the revoke time and time
  left for a `pending_revoke`, and a one-line hint ("re-run `rotate apply`
  after 07:12:00 UTC to revoke the old secret", "run `rotate rollback` with
  the same input, then `rotate apply` again", "consumer <ref> failed: see
  the audit log, ..."). When a rotation's last audit entry has an error,
  the redacted error is printed under its row. Finished rotations
  (`revoked`, `rolled_back`) are hidden unless you pass `--all`; a rollback
  still in progress is always shown. `--json` prints the same rows as an
  array described by [docs/status-schema.json](docs/status-schema.json).
  It exits 3 when any rotation is pending (`created`, `consumers_updated`,
  `verified`, `pending_revoke`, `failed`, `needs_rollback`, or being rolled
  back) and 0 otherwise, including when there is no state file ("no
  rotations"). `planned` rotations are listed but are not pending.
- `rotate.yaml` is loaded and validated (see
  [docs/rotate.example.yaml](docs/rotate.example.yaml)).
- AWS access keys are identified and checked with STS, signed with the
  leaked key itself.
- GitHub tokens (classic and fine-grained personal access tokens, OAuth app
  and GitHub App tokens) are identified by prefix and checked with `GET
  /user`; the plan shows the login, token type, classic scopes (fine-grained
  permissions are not readable through the API) and orgs. Apply asks for
  the new token in manual mode, naming the scopes to give it, checks it
  belongs to the same login, and revokes the leaked one through GitHub's
  credential revocation API, which needs no token of yours. Installation
  tokens (`ghs_`) are reported but not revoked: they expire within an hour.
  See [docs/permissions.md](docs/permissions.md).
- npm access tokens (`npm_`, granular and `npm login` session tokens) are
  identified by prefix and checked with `GET /-/whoami`; the plan shows the
  npm user and, from your own token list, the token's type, access,
  permissions, scopes, IP ranges and expiry. Set `ROTATE_NPM_TOKEN` (or
  `NPM_TOKEN`) to an `npm login` session token of the same account; without
  it the plan says the token is not visible to the operator account. Apply
  asks for the new granular token in manual mode, checks it belongs to the
  same user, and deletes the leaked one by its token id. An account that
  asks for a one-time password to delete tokens makes the revoke fail
  safely, naming the page to delete it on. See
  [docs/permissions.md](docs/permissions.md).
- OpenAI API keys (`sk-proj-`, `sk-svcacct-` and legacy `sk-` keys) are
  identified by prefix and checked with `GET /v1/models`. With an Admin API
  key in `OPENAI_ADMIN_KEY` (or the variable `providers.openai.admin_key_env`
  names), the plan shows the key's project, name, owner, created and last
  used times; apply creates a service account in the same project for the
  replacement, checks the new key is listed there, and deletes the leaked
  key (a user key by id; a service-account key by deleting its service
  account when that is its only key). Rollback deletes the replacement's
  service account. Without an admin key apply runs in manual mode and
  cannot revoke: the plan says to delete the key on the OpenAI dashboard.
  Admin keys (`sk-admin-`) are identified but not rotated. See
  [docs/permissions.md](docs/permissions.md).
- `plan` and `apply` search two real consumers, using the targets in
  `rotate.yaml`: GitHub Actions secrets, matched by name in the
  `consumers.github_actions.targets` repos and orgs and written as sealed
  values with the operator token from `ROTATE_GITHUB_TOKEN` or
  `GITHUB_TOKEN`; and AWS Secrets Manager entries named or tagged under
  `consumers.aws_secrets_manager`, matched by value (a plain value or a
  top-level JSON string field) and written as a new version with the
  standard AWS credentials. With those sections empty, neither makes a
  call.
- All four MVP providers register in release builds. The AWS IAM provider
  is complete: validity with the leaked key's one `sts:GetCallerIdentity`
  call, and scope, key creation, deactivation and reactivation with your
  own AWS credentials (see [docs/permissions.md](docs/permissions.md)). Mock
  providers exist only behind the `test-providers` cargo feature, for tests.

Not done yet:

- `rotate apply --json`. Resuming a manual-mode rotation after the process
  exited by pasting the same replacement again (such a rotation is marked
  `needs_rollback`).
- `rotate rollback` has no `--json` yet.

Progress is tracked in [docs/backlog.md](docs/backlog.md).

## Safety guarantees

These hold for every change; a pull request that breaks one is not merged.

1. **Secret values never leave memory in plain text.** They are never
   printed, logged, or written to disk, and they are held in zeroized
   buffers that are wiped on drop. Output, logs, the audit log and the state
   file show a fingerprint (`sha256:` and 16 hex characters) instead.
2. **`rotate plan` is a dry run.** It makes zero state-changing API calls.
   Tests prove this with mocks that record every call.
3. **Revoke is always the last step.** Any failure during `rotate apply`
   stops before the revoke and leaves the old secret working.
4. **No revoke while a consumer still holds the old secret.** rotate refuses
   to revoke a secret whose consumers could not all be updated, unless
   `--force` is given, and records the use of `--force` in the audit log.

### How the acceptance test proves the MVP

`tests/acceptance_mvp.rs` runs the release code path of the `rotate` binary
(the real AWS provider, Secrets Manager consumer and GitHub Actions
consumer) against one local wiremock server that models an AWS account and
the Actions secrets of a repository. A TruffleHog report leaks an AWS key
that one Secrets Manager entry and the repository's `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY` secrets hold. The test shows that `rotate plan`
lists the IAM user, all three consumer matches and the deactivate step
while no state-changing request reaches the server; that `rotate apply`
creates a new key, writes it to Secrets Manager and to both Actions
secrets (the test decrypts each sealed `PUT` with the repository's private
key), verifies it and then deactivates the old key; that the audit log has
an `ok` entry for every step; and that neither secret access key nor the
GitHub token appears in stdout, stderr, the trace log at `-vvv`, the audit
log, the state file or any request other than the one that must carry it.
It also covers a denied Actions write: the old key stays active, and the
rotation is recovered with `rotate rollback` and a fresh apply. CI runs it
on every pull request.

## Build from source

Needs Rust stable (1.94.1 or newer).

```sh
git clone https://github.com/smhasan94/rotate.git
cd rotate
cargo build --release
./target/release/rotate --help
```

Prebuilt Linux and macOS binaries will be attached to GitHub Releases from
the first tagged version.

## Quick start

Placeholder until the providers land; the commands are the intended flow.

```sh
# Dry run: show what would be created, updated and revoked.
rotate plan trufflehog-report.json

# One secret from stdin. Use --provider to skip identification.
pbpaste | rotate plan --stdin

# Apply the plan: type each rotation id when asked.
rotate apply trufflehog-report.json

# What is in progress or waiting for its overlap window; exits 3 if any.
rotate status

# Non-interactive, for CI: confirm by id.
rotate apply trufflehog-report.json --confirm rot-1a2b3c4d

# Manual replacement (GitHub, npm) without a terminal: supply the new token.
NEW_TOKEN=... rotate apply --stdin --confirm rot-1a2b3c4d --replacement-from-env NEW_TOKEN
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Everything requested was done. |
| 1 | A rotation step failed. The old secret is still valid unless the output says otherwise. |
| 2 | Bad arguments, bad configuration, or a subcommand that is not implemented yet. |
| 3 | Work is pending: `rotate apply` recorded a revoke waiting for its overlap window, or `rotate status` found a rotation that is pending, failed or needs rollback. |
| 101 | rotate panicked. This is a bug; the message is redacted like all other output. |

## Documentation

- [docs/requirements.md](docs/requirements.md): requirements, threat model
  and recorded decisions.
- [docs/report-formats.md](docs/report-formats.md): the TruffleHog and
  gitleaks fields rotate reads.
- [docs/rotate.example.yaml](docs/rotate.example.yaml): every config option
  with its default.
- [docs/permissions.md](docs/permissions.md): the operator permissions each
  provider needs.
- [CONTRIBUTING.md](CONTRIBUTING.md): checks, branches, commits and pull
  requests.
- [SECURITY.md](SECURITY.md): how to report a vulnerability.

## License

Apache-2.0. See [LICENSE](LICENSE).
