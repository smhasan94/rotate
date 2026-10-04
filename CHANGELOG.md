# Changelog

All notable changes to rotate are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and rotate uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/smhasan94/rotate/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/smhasan94/rotate/releases/tag/v0.1.0
