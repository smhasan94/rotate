# rotate: requirements

Status: approved 2026-09-29. Section 11 records the decisions the backlog is
built on.

## 1. Problem statement

Secret scanners (gitleaks, Betterleaks, TruffleHog, GitHub secret scanning)
are good at finding leaked credentials. Rotating them is still a manual,
risky and often skipped step. GitGuardian found that over 64% of secrets valid
in 2022 were still valid in January 2026.

Rotating a secret by hand means: confirm it is still live, work out what it can
reach, create a replacement, find every place the old value is used, update
each one, check nothing broke, then revoke the old value. Doing that under
incident pressure for many keys leads to outages (revoked before consumers were
updated) or to keys that are never revoked at all.

Commercial "one-click revoke" covers a short provider list and does not update
the consumers of the secret. Open source has only single-provider scripts.

rotate is an open-source CLI that does the whole loop safely: identify, check,
plan, replace, update consumers, verify, revoke, with an audit trail, and with
a dry run as the default.

## 2. Target users and jobs to be done

Platform and security engineers at startups and mid-size companies.

| User | Job to be done |
|------|----------------|
| Security engineer triaging a GitHub secret-scanning alert | Find out in seconds whether the key is still valid and what it can reach, then rotate it without waking the owning team. |
| Platform engineer during a supply-chain incident (Shai-Hulud, tj-actions style) | Rotate many keys quickly, in a repeatable way, without causing an outage, and prove afterwards what was rotated and when. |
| Engineer on call who inherited the key | Understand which CI secrets and secret-manager entries use the key before touching it, and roll back if a rotation goes wrong. |
| Team lead or auditor | Read a log of every rotation step: who, when, which provider, which key (by fingerprint), and the outcome. |

## 3. MVP scope

### In scope

1. Input: a TruffleHog JSON report, a gitleaks JSON report, or a single secret
   on stdin. rotate identifies the provider and checks whether the secret is
   still valid.
2. Provider plugins, one trait with these operations: `identify`,
   `check_valid`, `describe_scope`, `create_replacement`, `revoke`.
   MVP providers: AWS IAM access keys; GitHub tokens (classic and fine-grained
   personal access tokens, revoked through GitHub's credential revocation API);
   npm access tokens; OpenAI API keys.
3. Consumer updaters, one trait with `find` (where the secret is used) and
   `update`. MVP consumers: GitHub Actions repository and organization secrets
   (matched via a mapping in `rotate.yaml` or a name convention); AWS Secrets
   Manager entries.
4. Workflow commands:
   - `rotate plan` (default, dry run): shows exactly what would be created,
     updated and revoked, and which consumers cannot be updated automatically.
   - `rotate apply`: requires typed confirmation, then creates the replacement,
     updates consumers, verifies the new secret works, and revokes the old one
     after a configurable overlap window.
   - `rotate rollback`: restores the previous state where the provider allows it.
   - `rotate status`: shows in-progress rotations.
5. Audit: every step appended to a local JSON audit log with timestamp, actor,
   provider, secret fingerprint (never the value) and outcome. Re-running is
   idempotent.

### Out of scope for MVP

- Scanning or detection of secrets.
- Replacing a secrets manager (Vault, Infisical, Doppler).
- A GUI.
- Providers beyond the four above.
- Automatic triggering from GitHub webhooks. The CLI interface must be
  designed so a GitHub Action can call it later (non-interactive confirmation,
  machine-readable output).

Nice-to-haves that come up during planning go in a "Later" epic, not in MVP.

## 4. User stories

- US1. As a security engineer, I can pass a TruffleHog or gitleaks report to
  `rotate plan` and see, per finding, the provider, whether the secret is still
  valid, and what it can reach, without any change being made.
- US2. As a security engineer, I can paste a single secret on stdin and get the
  same answer for that one secret.
- US3. As a platform engineer, I can see the full plan before applying:
  what will be created, which consumers will be updated, which cannot be
  updated automatically, and what will be revoked.
- US4. As a platform engineer, I can run `rotate apply`, type the confirmation,
  and have the tool create the replacement, update every consumer, verify the
  new secret, and revoke the old one after the overlap window.
- US5. As a platform engineer, if any step fails, the tool stops before revoking
  and leaves my systems working on the old secret, and tells me what to do next.
- US6. As a platform engineer, I can run `rotate rollback` to put back the old
  secret in consumers and re-enable the old key where the provider supports it.
- US7. As an engineer on call, I can run `rotate status` to see rotations that
  are in progress or waiting for their overlap window to end.
- US8. As an auditor, I can read the audit log and see every step with a
  timestamp, actor, provider, fingerprint and outcome, and never a secret value.
- US9. As a platform engineer, I can re-run the same `rotate apply` after an
  interruption and it continues from where it stopped instead of creating a
  second replacement.
- US10. As a security engineer, I can refuse to let the tool revoke a secret
  whose consumers were not all updated, unless I pass `--force` on purpose.
- US11. As a CI author, I can call rotate non-interactively with explicit
  flags in place of the typed confirmation, and consume JSON output.

## 5. Functional requirements

### Input and identification

- FR1. Accept a TruffleHog JSON report (one JSON object per line) and a gitleaks
  JSON report (array of findings). Parse into a common finding model: raw secret
  (held in a zeroized buffer), detector hint, source location.
- FR2. Accept a single secret on stdin. An optional `--provider` flag skips
  identification.
- FR3. Identify the provider from the detector hint and the secret's format.
  Unknown providers are reported as "unsupported" and skipped, never treated as
  errors that stop the run.
- FR4. Deduplicate findings by fingerprint so a secret that appears in many
  files is rotated once.
- FR5. Check validity with the provider's cheapest read-only call. Report
  valid, invalid or unknown (network or permission error) per finding.
- FR6. Describe scope: what the key can reach, as far as the provider exposes
  it (for example the IAM user and attached policies, the GitHub login and
  scopes, the npm user and token type, the OpenAI project).

### Provider plugin contract

- FR7. One `Provider` trait with `identify`, `check_valid`, `describe_scope`,
  `create_replacement`, `revoke`, and a `restore` operation that may return
  "unsupported". Each operation reports which calls are read-only and which
  change state.
- FR8. A mock provider implements the full trait for tests and records every
  call, so tests can prove a dry run made zero state-changing calls.
- FR9. Providers where the API cannot mint a replacement use manual replacement
  mode: rotate asks the operator to paste the new secret (hidden input or
  stdin), verifies it belongs to the same account, then continues with the
  consumer update and revoke steps. (Decision D1.)

### Consumer updater contract

- FR10. One `Consumer` trait with `find` (returns consumer references and
  whether each is updatable), `update` and `restore`.
- FR11. Consumers are matched by an explicit mapping in `rotate.yaml` or by a
  per-provider name convention (decision D4). A consumer whose value cannot be read
  back (GitHub Actions secrets) is reported as "matched by name".
- FR12. A consumer that cannot be updated automatically is listed in the plan
  with the reason, and blocks the revoke step unless `--force` is given.

### Workflow

- FR13. `rotate plan` is the default command and makes zero state-changing
  API calls. It prints a plan per secret: replacement to create, consumers to
  update, consumers that cannot be updated, revoke action, and the overlap
  window. It supports `--json`.
- FR14. `rotate apply` prints the plan, requires the operator to type a
  confirmation phrase, and runs the steps in order: create replacement, update
  consumers, verify the new secret, wait for the overlap window, revoke the old
  secret. A `--confirm <rotation-id>` flag replaces typed input for
  non-interactive use.
- FR15. State after each step is persisted locally so an interrupted run can be
  resumed with the same command, and so `rotate status` can report progress.
  Resuming never repeats a completed state-changing step.
- FR16. The overlap window is configurable (flag and `rotate.yaml`). If it has
  not elapsed, `rotate apply` records the pending revoke and exits; running it
  again after the window completes the revoke. (Decision D2.)
- FR17. Any failure before the revoke step stops the run, records the failure,
  and leaves the old secret valid and consumers in a working state.
- FR18. `rotate rollback` restores consumers to the old value, re-enables the
  old secret where the provider supports it, and revokes the replacement.
  Because the old value is never stored, rollback needs the original report or
  stdin secret as input and matches it by fingerprint.
- FR19. `rotate status` lists in-progress rotations with the step reached, the
  time of the last step, and pending revoke times. Exit code is non-zero when
  any rotation is pending.

### Audit and idempotency

- FR20. Every step appends one JSON line to the audit log with: timestamp
  (UTC, RFC 3339), actor (OS user and hostname, overridable by an env var),
  rotation id, provider, secret fingerprint, replacement fingerprint if any,
  step, outcome, and error message (redacted) on failure.
- FR21. The fingerprint is a stable one-way digest of the secret value. The
  same value always gives the same fingerprint; the value cannot be recovered
  from it.
- FR22. Re-running plan or apply with the same input is idempotent: no
  duplicate replacements, no duplicate consumer updates, no duplicate revokes.

### Configuration

- FR23. `rotate.yaml` holds: consumer mappings, overlap window, audit log and
  state paths, and provider settings (for example AWS region, GitHub org, npm
  registry). Every path is overridable by flag or env var. Missing config is
  valid: defaults and name conventions apply.
- FR24. Operator credentials for the provider APIs come from the standard
  environment for each provider (AWS default credential chain, `GITHUB_TOKEN`,
  `NPM_TOKEN`, `OPENAI_ADMIN_KEY`). rotate does not use the leaked secret as
  its own credential. (Decision D3.)

## 6. Non-functional requirements

### Security (non-negotiable)

- NFR1. Secret values are never printed, logged, or written to disk in plain
  text. They live in zeroized memory buffers, and are wiped on drop. Where
  the OS allows, those buffers are locked in RAM so they are not swapped,
  and core dumps are disabled for the process (SHA-204); when locking is
  refused rotate still runs and warns once.
- NFR2. All output paths (stdout, stderr, tracing logs, audit log, state file,
  error messages, panic messages) pass through a redaction layer that replaces
  any known secret value with its fingerprint marker.
- NFR3. Dry run (`plan`) makes zero state-changing API calls. This is proven
  by tests against mocks that record every call.
- NFR4. Any failure during `apply` stops before the revoke step and leaves the
  system usable.
- NFR5. The tool refuses to revoke a secret whose consumers could not all be
  updated unless `--force` is given, and records the use of `--force` in the
  audit log.
- NFR6. Audit log and state files are created with owner-only permissions
  (0600) and are never world-readable.
- NFR7. Every ticket that touches secret values has a test proving the value
  never appears in stdout, stderr, logs or the audit log.

### Performance

- NFR8. Identification and parsing of a report with 1,000 findings completes
  in under 2 seconds on a laptop, excluding network calls.
- NFR9. Validity checks for many findings run concurrently with a bounded
  concurrency (default 8) and respect provider rate limits with retry and
  backoff.

### Portability

- NFR10. Runs on Linux (x86_64, aarch64) and macOS (x86_64, aarch64) from a
  single static-ish binary published on GitHub Releases. Windows is not a
  target for MVP but nothing should block it.
- NFR11. No runtime dependencies beyond the binary and system TLS roots.

### Developer experience

- NFR12. Rust stable, edition 2021, single crate. clap, tokio, reqwest,
  serde, zeroize, tracing.
- NFR13. Providers and consumers are traits with mock implementations. HTTP is
  tested with wiremock. Live tests run only with `ROTATE_LIVE_TESTS=1` and
  never in default CI.
- NFR14. CI runs `cargo fmt --check`, `cargo clippy --all-targets -- -D
  warnings`, `cargo test`, and `cargo deny check` on every PR on Linux and
  macOS.
- NFR15. Adding a provider means implementing one trait, registering it, and
  passing a shared conformance test suite.

## 7. Constraints

- Apache-2.0 license; all dependencies must have compatible licenses (enforced
  by cargo deny).
- GitHub has no API to create personal access tokens. npm granular tokens can
  only be created on the website, and legacy token creation needs the account
  password and one-time code. These providers cannot fully automate
  `create_replacement`.
- AWS IAM users can hold at most two access keys. If both slots are used,
  rotate cannot create a replacement without deleting a key.
- GitHub Actions secret values cannot be read back through the API, so
  consumer matching there is by name only.
- OpenAI key management requires an organization admin key; a plain API key
  can check its own validity but cannot revoke or create keys.
- Trunk-based development on `main`; all code through PRs; docs may be
  committed directly.

## 8. Assumptions

- A1. Fingerprint is `sha256:` plus the first 16 hex characters of SHA-256 of
  the secret value. For an AWS key pair it is computed over the secret access
  key. Secrets from the four MVP providers are high entropy, so an unsalted
  digest cannot be brute-forced.
- A2. Local state and the audit log live in `./.rotate/` under the working
  directory by default (`audit.jsonl`, `state.json`), overridable by config,
  flag or env var. (Decision D5.)
- A3. AWS revoke means deactivating the access key (reversible, supports
  rollback). Deleting deactivated keys is a Later ticket.
- A4. If an IAM user already has two access keys, rotate refuses to create a
  replacement and explains which key to remove. It never deletes a key on its
  own.
- A5. Verification of the new secret uses the same read-only call as
  `check_valid` (STS GetCallerIdentity, GitHub `GET /user`, npm `whoami`,
  OpenAI `GET /v1/models`), plus a check that the identity matches the old one.
- A6. The OpenAI replacement is a project service-account key created through
  the Admin API in the same project as the leaked key. Without an admin key,
  OpenAI falls back to manual replacement mode.
- A7. Default overlap window is 0 (revoke as soon as verification passes),
  because a leaked key should die fast; teams can set a longer window.
- A8. Typed confirmation is the rotation id printed in the plan.
- A9. Actor identity in the audit log is `user@hostname` from the OS, with
  `ROTATE_ACTOR` as an override for CI.

## 9. Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Consumer updated but new key not yet propagated (eventual consistency) | Brief outage after revoke | Overlap window; verify step; revoke last |
| Consumer missed because it is not in the mapping | Outage after revoke | Plan lists what was found; refuse revoke unless all found consumers updated; docs push teams to keep `rotate.yaml` complete |
| Provider API changes | Plugin breaks | wiremock tests pin expected requests; gated live tests catch drift |
| Redaction misses a value formatted differently (URL-encoded, base64) | Leak in logs | Redact by exact value and by provider pattern; leakage audit test with canary secret |
| Operator runs apply with insufficient permissions | Half-finished rotation | Plan checks operator permissions where possible; state store plus resume; failure stops before revoke |
| AWS two-key limit blocks rotation | Cannot rotate | Clear error in plan before apply |
| Manual replacement mode is error-prone | Wrong token pasted | Verify identity matches old secret before continuing |

## 10. Threat model

### What an attacker gains if rotate itself is compromised or misused

- Running rotate with a malicious report could point `create_replacement` and
  `revoke` at keys the attacker chose, causing denial of service by revoking
  live keys.
- A compromised binary or dependency would see every secret rotate handles,
  plus the operator's own credentials for AWS, GitHub, npm and OpenAI.
- A compromised consumer updater could write attacker-controlled values into
  CI secrets or Secrets Manager.
- Reading the audit log or state file could reveal which keys exist and their
  rotation history.
- A stolen `--force` run could revoke a key whose consumers were not updated.

### How the design limits that

- Dry run by default and typed confirmation for apply. Non-interactive use
  needs an explicit rotation id, so a script cannot accidentally apply a plan
  it did not print.
- The plan lists every state-changing action before it runs. Nothing outside
  the plan is executed.
- Secret values exist only in zeroized buffers, never on disk, never in
  logs. The audit log holds fingerprints only, so its disclosure does not
  reveal secrets. The buffers are locked out of swap where the OS allows,
  and the process writes no core dump and, on Linux, cannot be attached to
  by other processes of the same user.
- rotate uses the operator's existing credentials and does not need long-lived
  credentials of its own. It never uses the leaked secret as a credential
  (decision D3).
- Revoke is the last step and is skipped on any earlier failure. `--force`
  is recorded in the audit log with the actor.
- Supply chain: cargo deny for advisories and licenses, minimal dependency
  set, reproducible release builds with checksums, and no network access in
  tests except to wiremock.
- Least privilege: the docs list the minimum operator permissions per provider
  and consumer so teams can scope the operator credential.
- Verification before revoke: the new secret must prove it works and belongs to
  the same identity, so a swapped or attacker-supplied replacement fails closed.

## 11. Decisions (resolved 2026-09-29)

Each question was raised during backlog planning and answered by the project
owner. The backlog in `docs/backlog.md` is built on these.

- D1. Providers whose API cannot create a replacement (GitHub PATs, npm
  tokens) use manual replacement mode: rotate prompts for the new token with
  hidden input, verifies it belongs to the same account, then updates
  consumers and revokes the old one. (Ticket SHA-257.)
- D2. Overlap window is exit and resume: `rotate apply` updates and verifies
  consumers, records a pending revoke, and exits with code 3. A second
  `rotate apply` after the window completes the revoke. `--wait` blocks for
  short windows. Default window is 0. (Ticket SHA-258.)
- D3. rotate never uses the leaked secret as its own credential in MVP.
  Operator credentials come from the standard environment only. Self-rotation
  is in the Later epic. (Ticket SHA-196.)
- D4. Consumers are matched by a per-provider name convention plus explicit
  mappings in `rotate.yaml`: Actions secrets `AWS_ACCESS_KEY_ID` and
  `AWS_SECRET_ACCESS_KEY` (AWS), `GH_TOKEN` or `GH_PAT`
  (GitHub), `NPM_TOKEN` (npm), `OPENAI_API_KEY` (OpenAI), across the repos and
  orgs listed in `rotate.yaml`. Secrets Manager entries are matched by value
  fingerprint. Actions secrets are always "matched by name" because their
  values cannot be read back. (Tickets SHA-252, SHA-253.)
- D5. Audit log and state live in `./.rotate/` under the working directory by
  default (`audit.jsonl`, `state.json`), overridable by flag, env var or
  config. (Ticket SHA-214.)
