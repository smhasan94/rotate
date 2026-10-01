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
- `rotate.yaml` is loaded and validated (see
  [docs/rotate.example.yaml](docs/rotate.example.yaml)).

Not done yet:

- The four real providers. Until they land, a release build reports every
  secret as unsupported. Mock providers exist only behind the
  `test-providers` cargo feature, for tests.
- Real consumers (GitHub Actions secrets, AWS Secrets Manager), so a
  release build finds no consumers yet.
- `rotate apply`, `rotate rollback` and `rotate status`. These are stubs.

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

## Build from source

Needs Rust stable (1.91 or newer).

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

# Apply the plan (typed confirmation). Not implemented yet.
rotate apply trufflehog-report.json
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Everything requested was done. |
| 1 | A rotation step failed. The old secret is still valid unless the output says otherwise. |
| 2 | Bad arguments, bad configuration, or a subcommand that is not implemented yet. |
| 3 | Work is pending, for example a revoke waiting for its overlap window (`rotate status`). |
| 101 | rotate panicked. This is a bug; the message is redacted like all other output. |

## Documentation

- [docs/requirements.md](docs/requirements.md): requirements, threat model
  and recorded decisions.
- [docs/report-formats.md](docs/report-formats.md): the TruffleHog and
  gitleaks fields rotate reads.
- [docs/rotate.example.yaml](docs/rotate.example.yaml): every config option
  with its default.
- [CONTRIBUTING.md](CONTRIBUTING.md): checks, branches, commits and pull
  requests.
- [SECURITY.md](SECURITY.md): how to report a vulnerability.

## License

Apache-2.0. See [LICENSE](LICENSE).
