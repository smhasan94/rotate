# rotate

[![ci](https://github.com/smhasan94/rotate/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/smhasan94/rotate/actions/workflows/ci.yml)

rotate is an open-source CLI that revokes and rotates leaked secrets safely,
end to end. Give it a TruffleHog or gitleaks report, or a single secret on
stdin. It works out which provider each secret belongs to and whether it is
still valid, creates a replacement, updates every place that uses the secret
(GitHub Actions secrets, AWS Secrets Manager), checks that the new secret
works, and only then revokes the old one. Every step goes to a local audit
log that holds fingerprints, never values.

![Demo: rotate plan shows the rotation of a leaked AWS key used by a GitHub
Actions secret and a Secrets Manager entry, rotate apply rotates it after the
typed confirmation, rotate status shows it done, and the audit log holds
fingerprints only](docs/demo/demo.gif)

MVP providers: AWS IAM access keys, GitHub tokens, npm access tokens and
OpenAI API keys.

## Status

The latest release is v0.2.0. v0.1.0 was the first: the MVP flow end to
end, with prebuilt Linux and macOS binaries (see [Install](#install)). What
changed in each version is in [CHANGELOG.md](CHANGELOG.md).

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
- `rotate plan --check-permissions` also probes your own permissions,
  read-only, before you apply: an IAM policy simulation
  (`iam:SimulatePrincipalPolicy`) for the AWS actions rotate will call, and
  a public-key read per GitHub Actions target. A missing AWS action becomes
  a blocker; an Actions target the token cannot write is listed as
  "token lacks Secrets: write". [docs/permissions.md](docs/permissions.md) has the
  minimal IAM policy and the GitHub, npm and OpenAI token requirements.
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
- Revoke by hand: when rotate cannot revoke the old secret itself (an
  OpenAI key without an Admin API key or one the Admin API cannot delete,
  a GitHub App installation token, a legacy-format GitHub token), `plan`
  shows the manual revoke row and a blocker, and `apply` updates the
  consumers, verifies the replacement, waits out the overlap window, then
  stops at step `revoke_manual` with the provider's instructions ("rot-3:
  revoke by hand: ... delete it at https://platform.openai.com/api-keys;
  the replacement is live and verified") and exits 4. The audit log gets a
  `revoke` entry with outcome `skipped` and the instructions. Once you have
  deleted the old secret, re-run `rotate apply` with the same input: a
  read-only check finds it no longer works and records the rotation
  `revoked` (a `revoke` entry with outcome `ok`, "revoked by hand,
  confirmed by check_valid"), with no state-changing call. While it still
  works the re-run makes only that check and exits 4 again.
- Manual replacement mode, for providers whose API cannot mint a
  replacement (GitHub and npm tokens, and OpenAI keys unless you opt in to
  a broader replacement). Apply prints what to create, then
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
  secret, consumers are still restored but hold a revoked secret: the
  summary says so and rollback exits 1, so create a new credential and run
  `rotate apply` again. A pasted (manual) replacement has to be revoked by
  hand.
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
  `verified`, `pending_revoke`, `failed`, `needs_rollback`, `revoke_manual`
  (the hint is the provider's instructions), or being rolled back) and 0 otherwise, including when there is no state file ("no
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
  `NPM_TOKEN`) to an `npm login` session token of the same account (a
  granular token cannot list tokens; a session token lasts two hours, so
  run `npm login` shortly before an unattended run); without it the plan
  says the token is not visible to the operator account and shows a revoke
  blocker. Apply
  asks for the new granular token in manual mode, checks it belongs to the
  same user, and deletes the leaked one by its token id. An account that
  asks for a one-time password to delete tokens gets a hidden prompt at
  that moment (or the code from `ROTATE_NPM_OTP`); without a code the
  revoke fails safely, naming the page to delete it on. See
  [docs/permissions.md](docs/permissions.md).
- OpenAI API keys (`sk-proj-`, `sk-svcacct-` and legacy `sk-` keys) are
  identified by prefix and checked with `GET /v1/models`. With an Admin API
  key in `OPENAI_ADMIN_KEY` (or the variable `providers.openai.admin_key_env`
  names), the plan shows the key's project, name, owner, created and last
  used times. By default apply asks you to paste a new key with Restricted
  permissions matching the leaked one, because a replacement rotate creates
  is a service account with all permissions in the project, which may be
  broader. With `--allow-broader-replacement` (or
  `providers.openai.allow_broader_replacement: true`) apply creates that
  service account instead, and the plan and audit log mark the scope
  widening. Either way apply checks the new key is listed in the same
  project, and deletes the leaked
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

## Install

### Homebrew

On macOS, and on Linux with Homebrew:

```sh
brew install smhasan94/rotate/rotate
rotate --version
```

The formula lives in the tap
[smhasan94/homebrew-rotate](https://github.com/smhasan94/homebrew-rotate)
and installs the release binaries below, checked against their published
checksums. Every release updates it; upgrade with
`brew upgrade smhasan94/rotate/rotate`. Use the full name: Homebrew 6 and
later only load a formula from a third-party tap that you installed by its
full name or trusted with `brew trust`.

### Prebuilt binaries

Prebuilt binaries for Linux and macOS (x86_64 and aarch64) are attached to
each [GitHub Release](https://github.com/smhasan94/rotate/releases), with a
`SHA256SUMS` file. This downloads the one for your machine, checks its
checksum and installs it in `~/.local/bin`:

<!-- install:start -->
```sh
VERSION=0.2.0
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) TARGET=x86_64-unknown-linux-gnu ;;
  Linux-aarch64) TARGET=aarch64-unknown-linux-gnu ;;
  Darwin-x86_64) TARGET=x86_64-apple-darwin ;;
  Darwin-arm64) TARGET=aarch64-apple-darwin ;;
esac
NAME="rotate-$VERSION-$TARGET"
curl -fsSLO "https://github.com/smhasan94/rotate/releases/download/v$VERSION/$NAME.tar.gz"
curl -fsSLO "https://github.com/smhasan94/rotate/releases/download/v$VERSION/SHA256SUMS"
grep " $NAME.tar.gz\$" SHA256SUMS | { sha256sum -c - 2>/dev/null || shasum -a 256 -c -; }
tar -xzf "$NAME.tar.gz" rotate
mkdir -p ~/.local/bin && install -m 0755 rotate ~/.local/bin/rotate
~/.local/bin/rotate --version
```
<!-- install:end -->

Add `~/.local/bin` to your `PATH` if it is not there already. The Linux
binaries need glibc 2.35 or newer (Ubuntu 22.04, Debian 12). There is no
Windows build and no crates.io package.

### Build from source

Needs Rust stable (1.94.1 or newer).

```sh
git clone https://github.com/smhasan94/rotate.git
cd rotate
cargo build --release
./target/release/rotate --help
```

## Quick start

The full walkthrough is [docs/usage.md](docs/usage.md).

```sh
# 1. Say where your secrets are used (see docs/config.md).
cat > rotate.yaml <<'YAML'
consumers:
  github_actions:
    targets: [acme/api]
  aws_secrets_manager:
    secrets: [prod/app]
YAML

# 2. Dry run: show what would be created, updated and revoked. Changes nothing.
rotate plan trufflehog-report.json

# One secret instead of a report: paste it, then Ctrl-D. Never pass it as an argument.
rotate plan --stdin

# 3. Apply: type each rotation id when asked.
rotate apply trufflehog-report.json

# 4. What is in progress or waiting for its overlap window; exits 3 if any.
rotate status

# Undo a rotation: give the same input again.
rotate rollback trufflehog-report.json
```

- [docs/usage.md](docs/usage.md): install, first run, reading the plan,
  apply, the overlap window, rollback, status, every flag and the exit
  codes.
- [docs/config.md](docs/config.md): every `rotate.yaml` field with its
  default, environment variables and name conventions.
- [docs/security.md](docs/security.md): the four safety guarantees, the
  audit log, fingerprints, file permissions and the limits.
- [docs/non-interactive.md](docs/non-interactive.md): `--confirm`,
  `--replacement-from-env`, `--json`, exit codes for scripts, and a
  scheduled GitHub Actions workflow.

## Exit codes

`0` done, `1` a step failed (the old secret still works unless the output
says otherwise), `2` bad arguments or configuration (nothing changed), `3`
work pending, `4` revoke the old secret by hand. Details per command:
[docs/usage.md](docs/usage.md#9-exit-codes) and, for scripts,
[docs/non-interactive.md](docs/non-interactive.md#exit-codes).

## Documentation

- [docs/usage.md](docs/usage.md): the usage guide.
- [docs/config.md](docs/config.md): the `rotate.yaml` reference.
- [docs/security.md](docs/security.md): the security model and its limits.
- [docs/non-interactive.md](docs/non-interactive.md): scripts, CI and exit
  codes.
- [docs/requirements.md](docs/requirements.md): requirements, threat model
  and recorded decisions.
- [docs/report-formats.md](docs/report-formats.md): the TruffleHog and
  gitleaks fields rotate reads.
- [docs/rotate.example.yaml](docs/rotate.example.yaml): an annotated
  `rotate.yaml` with every option.
- [docs/providers.md](docs/providers.md): what rotate automates for each
  provider and consumer, what is manual or unsupported, and what to prepare
  before an incident.
- [docs/permissions.md](docs/permissions.md): the operator permissions each
  provider needs.
- [CONTRIBUTING.md](CONTRIBUTING.md): checks, branches, commits and pull
  requests.
- [SECURITY.md](SECURITY.md): how to report a vulnerability.

## License

Apache-2.0. See [LICENSE](LICENSE).
