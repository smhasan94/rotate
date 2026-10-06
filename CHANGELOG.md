# Changelog

All notable changes to rotate are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and rotate uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `rotate apply` revokes every GitHub token of a run together, in one
  request to GitHub's credential revocation API per 1000 tokens, after
  every rotation has passed create, update, verify and the revoke gate.
  A rate-limited request fails the rotations still to revoke, with the old
  secret still valid and the time to re-run apply. (SHA-286)

### Changed

- An endpoint URL with a query string or fragment, even an empty `?` or
  `#`, is refused with exit 2. The endpoint warning prints the URL as
  written, so a token in the query would have reached stderr. (SHA-332)

### Fixed

- The "revoking N github tokens in one request" notice counts only the
  tokens the request carries, leaving out installation and legacy-format
  tokens. (SHA-330)

### Security

- Core dumps are off at startup: the core file limit is 0, soft and hard,
  and on Linux the process is also marked not dumpable. Secret buffers are
  locked in RAM with `mlock`, so they are not written to swap. If the OS
  refuses, rotate keeps working and prints one warning. (SHA-204)

## [0.2.0] - 2026-10-05

Safety fixes found after the first release, and npm one-time passwords.
Two changes can affect scripts: `rotate rollback` now exits 1 when the
restored consumers are left holding a revoked secret, and an `http://`
endpoint URL to a host other than loopback is now refused.

### Added

- npm accounts that ask for a one-time password to delete tokens: at the
  delete, rotate takes a code from `ROTATE_NPM_OTP` (one delete per run) or
  a hidden prompt on the terminal naming the npm user, and retries once
  with the `npm-otp` header. Rollback's delete of a replacement does the
  same. Without a code, or with one npm rejects, the revoke still fails
  safely, naming the page to delete the token on.

### Changed

- `rotate rollback` exits 1 when the old secret could not be reactivated
  (GitHub, npm and OpenAI tokens, or after a revoke by hand): the restored
  consumers hold a revoked secret. The summary counts such rotations apart
  ("with the old secret still revoked") and names the consumers, the plan
  warns before you confirm, `rotate status` says so in the hint, and an
  interrupted rollback finished by a re-run exits 1 too. It used to exit 0
  with only a warning.

### Security

- Endpoint URLs in `rotate.yaml` (`providers.aws.endpoint_url`,
  `providers.github.api_url`, `providers.npm.registry`,
  `providers.openai.api_url`) must be `https://`, except `http://` to a
  loopback host, and must not carry a user name or password. A tampered
  config could otherwise send new secrets and operator tokens in clear
  text. The error never repeats the URL.
- `rotate plan` and `rotate apply` print a `warning:` line for each
  endpoint that differs from its default, before apply asks for
  confirmation; `plan --json` adds a `warnings` array.

### Known limits

- Not yet tested against the live services: every test runs against mock
  servers built from the providers' documentation. Run `rotate plan` first
  and review the plan before `rotate apply`.
- GitHub and npm tokens are rotated in manual replacement mode: you create
  the new token and paste it. OpenAI keys are manual too, unless you opt in
  to a broader replacement.
- npm revoke needs an `npm login` session token as the operator token,
  which lasts two hours. An account that asks for a one-time password
  needs a terminal or `ROTATE_NPM_OTP` at the moment of the revoke, so an
  unattended run with an overlap window cannot revoke it.
- AWS keys are deactivated, not deleted. After a rollback the replacement
  key stays inactive on the IAM user; delete it yourself.
- OpenAI keys without an Admin API key, GitHub App installation tokens and
  legacy-format GitHub tokens end in revoke by hand.
- Each GitHub token is revoked with its own request; GitHub allows 60 an
  hour, so an incident with more tokens than that needs several runs.
- No `--json` for `apply` or `rollback` yet. No Windows build.

## [0.1.0] - 2026-10-04

The first release: the MVP flow end to end, from a scanner report to a
revoked secret, for four providers and two consumers.

### Added

- Input: TruffleHog (`--json`) and gitleaks (`-f json`) reports, or one
  secret on stdin with `--stdin`. Findings are deduplicated by
  fingerprint, and the provider of each one is identified.
- `rotate plan`: a dry run that makes no state-changing API call. It checks
  each secret's validity and shows the replacement to create, the
  consumers to update (and any that cannot be), the revoke action, the
  overlap window and any blockers. `--json` output follows
  `docs/plan-schema.json`. `--check-permissions` probes your own
  permissions, read-only.
- `rotate apply`: confirm by typing each rotation id (or pass `--confirm`
  or `--all`). It then creates the replacement, updates every consumer,
  verifies the replacement belongs to the same owner and revokes the old
  secret last. Any earlier failure stops before the revoke. Revoking while
  a consumer was not updated needs `--force`, which is audited. Supports an
  overlap window (`--overlap`, exit 3 until it has passed, or `--wait`),
  idempotent re-runs that resume where the last run stopped, and revoke by
  hand (exit 4) when rotate cannot revoke a secret itself.
- `rotate rollback`: reactivates the old secret where the provider allows
  it, restores every updated consumer, then revokes the replacement.
- `rotate status`: in-progress rotations, read from local files with no
  network call. `--json` output follows `docs/status-schema.json`.
- Providers:
  - AWS IAM access keys: create a new key, deactivate the old one,
    reactivate it on rollback.
  - GitHub tokens: classic and fine-grained PATs, OAuth and App tokens.
    Revoked through GitHub's credential revocation API.
  - npm access tokens: granular and session tokens.
  - OpenAI API keys: user, service account and legacy keys.
- Consumers: GitHub Actions repository and organization secrets, matched by
  name convention or a `rotate.yaml` mapping; AWS Secrets Manager entries,
  matched by value.
- Audit log `.rotate/audit.jsonl`: every step with timestamp, actor,
  provider, fingerprint and outcome. State in `.rotate/state.json`. Both
  files are mode 0600.
- Safety: secret values are held in zeroized memory and never appear in
  output, logs, the audit log or the state file; every log line passes
  through a redaction layer. CI checks this with a canary leakage sweep
  over every command.
- Prebuilt binaries for Linux (x86_64, aarch64) and macOS (x86_64,
  aarch64), with `SHA256SUMS`.

### Known limits

- GitHub and npm tokens are rotated in manual replacement mode: you create
  the new token and paste it, because their APIs cannot mint one. OpenAI
  keys are manual too, unless you opt in to a broader replacement with
  `--allow-broader-replacement` or
  `providers.openai.allow_broader_replacement`.
- npm revoke needs an `npm login` session token as the operator token.
  Session tokens last two hours, so an unattended run needs a fresh
  `npm login` shortly before it. An account that asks for a one-time
  password to delete tokens cannot be revoked by rotate.
- AWS keys are deactivated, not deleted, so rollback can reactivate them.
  After a rollback the replacement key stays inactive on the IAM user;
  delete it yourself.
- OpenAI keys cannot be revoked without an Admin API key; GitHub App
  installation tokens and legacy-format GitHub tokens cannot be revoked by
  rotate. These end in revoke by hand.
- A manual-mode rotation stopped before every consumer was updated cannot
  be resumed by a new process (rotate never stores the replacement); it
  needs `rotate rollback`, then `rotate apply` again.
- No `--json` for `apply` or `rollback` yet. No Windows build.

[Unreleased]: https://github.com/smhasan94/rotate/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/smhasan94/rotate/releases/tag/v0.2.0
[0.1.0]: https://github.com/smhasan94/rotate/releases/tag/v0.1.0
