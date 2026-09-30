# rotate

Open-source CLI that revokes and rotates leaked secrets safely, end to end.

## Brief

Problem: secret scanners (gitleaks, Betterleaks, TruffleHog, GitHub secret
scanning) find leaked credentials, but rotating them is manual, risky and often
skipped. GitGuardian found over 64% of secrets valid in 2022 were still valid in
January 2026. Commercial one-click revoke covers a short provider list and does
not update the places that use the secret. Open source has only
single-provider scripts.

Users: platform and security engineers at startups and mid-size companies;
teams responding to GitHub secret-scanning alerts or supply-chain incidents
(Shai-Hulud, tj-actions style) who must rotate many keys quickly without an
outage.

MVP scope:

1. Input: a TruffleHog or gitleaks JSON report, or a single secret on stdin.
   Identify the provider and check whether the secret is still valid.
2. Provider plugins implementing: identify, check_valid, describe_scope,
   create_replacement, revoke. MVP providers: AWS IAM access keys; GitHub
   tokens (classic and fine-grained PATs, using GitHub's credential revocation
   API); npm access tokens; OpenAI API keys.
3. Consumer updaters implementing: find and update. MVP consumers: GitHub
   Actions repository and organization secrets (matched via a mapping in
   rotate.yaml or a name convention); AWS Secrets Manager entries.
4. Workflow: `rotate plan` is the default dry run and shows exactly what would
   be created, updated and revoked, plus which consumers cannot be updated
   automatically. `rotate apply` requires typed confirmation and runs: create
   replacement, update consumers, verify the new secret works, revoke the old
   one after a configurable overlap window. `rotate rollback` restores the
   previous state where the provider allows it. `rotate status` shows
   in-progress rotations.
5. Audit: every step appended to a local JSON audit log with timestamp, actor,
   provider, secret fingerprint (never the value) and outcome. Re-running is
   idempotent.

Safety requirements (non-negotiable): secret values are never printed, logged
or written to disk in plain text and are held in zeroized memory buffers; dry
run makes zero state-changing API calls; any failure during apply stops before
the revoke step and leaves the system usable; the tool refuses to revoke a
secret whose consumers could not all be updated unless `--force` is given.

Out of scope for MVP: scanning or detection, replacing a secrets manager
(Vault, Infisical, Doppler), a GUI, providers beyond the four, automatic
triggering from GitHub webhooks (design the interface so a GitHub Action can
call it later).

Success for MVP: given a TruffleHog report with a leaked AWS key referenced by
one GitHub Actions secret and one Secrets Manager entry, `rotate plan` shows
the full plan with no changes made, and `rotate apply` rotates it end to end:
old key revoked, both consumers updated, complete audit log, and the secret
value appearing nowhere in output or logs.

Full requirements, threat model and the five recorded decisions (manual
replacement mode, exit-and-resume overlap window, no self-rotation, name
convention plus mapping for consumers, `./.rotate/` for state):
`docs/requirements.md`. Backlog with Linear identifiers: `docs/backlog.md`.

## Engineering conventions

- Rust stable, edition 2021, single crate to start (split into a workspace only
  when a ticket calls for it). clap for the CLI, tokio and reqwest for API
  calls, serde for config and reports, zeroize for secret memory, tracing for
  logs with a redaction layer. Apache-2.0 license. Binaries via GitHub Releases.
- Provider and consumer plugins are traits with mock implementations; HTTP is
  tested with wiremock. Live integration tests against real accounts run only
  when `ROTATE_LIVE_TESTS=1` is set and never in default CI.
- Tooling: cargo fmt --check, cargo clippy --all-targets -- -D warnings, cargo
  test, cargo deny check for licenses and advisories. GitHub Actions runs all
  four on every PR on Linux and macOS.
- Git: trunk-based on main. Branch names are the lowercase Linear identifier, a
  hyphen, and a short slug of the ticket title (example:
  `sha-42-zeroized-secret-type`). Conventional commits. All code changes go
  through a PR; `docs/plans` and `docs/backlog.md` may be committed directly to
  main.
- Linear: project "rotate", team "Shakooky". Workflow states: Todo, In
  Progress, In Review, Done.
- Definition of done: every T-case in the ticket passes in CI, fmt, clippy and
  cargo deny pass, docs updated, PR reviewed and merged.

## Safety rules for every change

- Secret values never appear in stdout, stderr, tracing output, the audit log,
  the state file, panic messages or test snapshots. Any ticket that touches
  secret values includes a test proving this.
- `rotate plan` makes zero state-changing API calls. Tests prove this with
  mocks that record every call.
- Revoke is always the last step and is skipped on any earlier failure.

## Commands

Run all four before opening a PR. CI runs the same commands.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo deny check
```

Install the extra tools once:

```sh
rustup component add rustfmt clippy
cargo install cargo-deny --locked
```

Live integration tests (never in default CI; need real credentials in the
environment):

```sh
ROTATE_LIVE_TESTS=1 cargo test --all-features -- --ignored live_
```

Build a release binary:

```sh
cargo build --release
```

## Ticket template

Every Linear ticket uses these sections exactly: Context, Scope (in and out),
Acceptance criteria (AC1, AC2, ... as Given/When/Then), Test plan (T1 (unit or
integration) - covers ACn - ...), Definition of done, Dependencies (Blocked
by: identifiers or "none"). Every AC has at least one T-case; every T-case
names an AC.
