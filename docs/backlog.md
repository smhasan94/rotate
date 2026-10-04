# rotate backlog

Mirror of the Linear project "rotate" (team Shakooky, `P-SHA-9`), created
2026-09-29. Linear is the source of truth for status; this file records the
structure, estimates and dependency order so a reader without Linear access can
follow the plan.

Epics are parent issues labelled `Epic`. Tickets are sub-issues. Every ticket
is a vertical slice finishable in one day or less, has at most three blockers,
and is independently testable. Every ticket description follows the template
in `CLAUDE.md`. Estimates are in points (1 = a few hours, 2 = most of a day,
3 = a full day).

Decisions the backlog is built on are in `docs/requirements.md` section 11.
Implementation plans, one file per ticket, live in `docs/plans/` and are also
posted as a comment titled "Implementation plan" on the Linear ticket.

## Epic 1: Repo scaffolding (SHA-186)

Ends with: a CI-green crate that prints its version, subcommand stubs, and
release binaries on tag.

| Ticket | Title | Est | Blocked by |
|--------|-------|-----|------------|
| SHA-194 | Crate skeleton with clap subcommand stubs | 1 | none |
| SHA-212 | CI workflow with fmt, clippy, test and cargo deny on Linux and macOS | 1 | SHA-194 |
| SHA-213 | README skeleton, CONTRIBUTING, SECURITY.md and PR template | 1 | SHA-194 |
| SHA-215 | Release workflow publishing Linux and macOS binaries to GitHub Releases | 2 | SHA-212 |
| SHA-216 | Test harness conventions: wiremock helper, call recorder and live-test gate | 1 | SHA-212 |

## Epic 2: Secret-handling core (SHA-187)

Ends with: a library that holds, fingerprints, redacts and audits secrets, with
tests proving the value never leaks. Comes before any provider.

| Ticket | Title | Est | Blocked by |
|--------|-------|-----|------------|
| SHA-214 | rotate.yaml config loader with validation and overrides | 2 | SHA-194 |
| SHA-217 | SecretValue type: zeroized buffer, no Debug or Display leak, fingerprint | 2 | SHA-216 |
| SHA-218 | Redacting tracing layer: scrub known values and provider patterns from logs | 2 | SHA-217 |
| SHA-219 | Append-only JSONL audit log with 0600 permissions | 2 | SHA-217 |
| SHA-220 | Rotation state store: atomic 0600 JSON file with lock for resume, status and rollback | 2 | SHA-217 |
| SHA-246 | Redacted console writer, error Display and panic hook | 1 | SHA-218 |

## Epic 3: Workflow engine with mocks (SHA-188)

Ends with: the full plan, apply, rollback and status loop working against a
mock provider and mock consumer.

| Ticket | Title | Est | Blocked by |
|--------|-------|-----|------------|
| SHA-221 | Provider trait, registry and MockProvider that records every call | 2 | SHA-217 |
| SHA-222 | Consumer trait and MockConsumer with find, update, restore and not-updatable reasons | 2 | SHA-217 |
| SHA-223 | Report parsers: TruffleHog NDJSON and gitleaks JSON into a common finding model | 2 | SHA-217 |
| SHA-247 | Single secret on stdin with optional --provider override | 1 | SHA-223 |
| SHA-248 | Identify providers, dedupe by fingerprint and check validity concurrently | 2 | SHA-221, SHA-223 |
| SHA-249 | Provider and consumer conformance test suite | 2 | SHA-221, SHA-222 |
| SHA-250 | Planner and `rotate plan`: dry run with human table and --json, zero mutations | 3 | SHA-222, SHA-248, SHA-214 |
| SHA-254 | `rotate apply` happy path: typed confirmation, create, update, verify, revoke, state and audit | 3 | SHA-250, SHA-219, SHA-220 |
| SHA-256 | Apply safety rules: stop before revoke on failure, refuse revoke without --force, record force | 2 | SHA-254 |
| SHA-257 | Manual replacement mode: hidden prompt for a pasted replacement with identity check | 2 | SHA-254 |
| SHA-258 | Resume, idempotency and overlap window: re-run skips completed steps, pending revoke, --wait | 3 | SHA-256 |
| SHA-259 | `rotate rollback`: restore consumers, reactivate old secret where supported, revoke replacement | 2 | SHA-256 |
| SHA-263 | `rotate status`: list in-progress and pending rotations with non-zero exit when any pending | 1 | SHA-220, SHA-258 |

## Epic 4: AWS provider and Secrets Manager consumer (SHA-189)

Ends with: a real AWS key referenced by a Secrets Manager entry can be planned,
rotated and rolled back.

| Ticket | Title | Est | Blocked by |
|--------|-------|-----|------------|
| SHA-251 | AWS IAM provider read side: identify, check_valid via STS, describe_scope via IAM | 2 | SHA-249 |
| SHA-252 | AWS Secrets Manager consumer: find by fingerprint, JSON-key aware update, restore | 3 | SHA-249 |
| SHA-255 | AWS IAM provider write side: create replacement, verify, revoke by deactivation, restore, two-key refusal | 3 | SHA-251 |
| SHA-264 | AWS end-to-end with wiremock: report to plan to apply to rollback, with redaction proof | 2 | SHA-255, SHA-252, SHA-259 |

## Epic 5: GitHub consumer and provider, MVP acceptance (SHA-190)

Ends with: the MVP success scenario passes in CI.

| Ticket | Title | Est | Blocked by |
|--------|-------|-----|------------|
| SHA-253 | GitHub Actions secrets consumer: find by name convention or mapping, sealed-box update, restore | 3 | SHA-249 |
| SHA-260 | GitHub token provider: identify classic and fine-grained PATs, check and scope, revoke via credential revocation API, manual replacement | 3 | SHA-249, SHA-257 |
| SHA-267 | MVP acceptance test: AWS key used by one Actions secret and one Secrets Manager entry, plan then apply end to end | 2 | SHA-264, SHA-253 |
| SHA-270 | Operator permission docs: minimum IAM policy and GitHub token scopes for rotate | 1 | SHA-267 |

## Epic 6: npm and OpenAI providers (SHA-191)

Ends with: all four MVP providers pass the conformance suite.

| Ticket | Title | Est | Blocked by |
|--------|-------|-----|------------|
| SHA-261 | npm token provider: identify, check via whoami, scope via token list, revoke via token delete, manual replacement | 2 | SHA-249, SHA-257 |
| SHA-262 | OpenAI API key provider: identify, check via models, scope and revoke via Admin API, service-account replacement with manual fallback | 3 | SHA-249, SHA-257 |
| SHA-266 | Provider and consumer matrix doc: automated, manual or unsupported per operation | 1 | SHA-261, SHA-262 |

npm operator token (corrected by SHA-292): the SHA-261 text said a
long-lived automation or granular token would do. Neither does. The npm operator token must be an `npm login` session token for
the same account as the leaked token: npm's token list accepts no other
kind, granular access tokens included. Session tokens last two hours, so
npm revoke cannot run unattended on a stored token. Sources:
`docs/plans/SHA-292.md`.

## Epic 7: Hardening and v0.1.0 release (SHA-192)

Ends with: v0.1.0 on GitHub Releases with docs.

| Ticket | Title | Est | Blocked by |
|--------|-------|-----|------------|
| SHA-265 | Leakage audit test: canary secret through every command, grep every output and file | 2 | SHA-259 |
| SHA-268 | Live integration tests for AWS and GitHub behind ROTATE_LIVE_TESTS=1 with manual-dispatch workflow | 2 | SHA-264, SHA-253 |
| SHA-269 | User docs: usage guide, rotate.yaml reference, security model, non-interactive use | 2 | SHA-266 |
| SHA-271 | v0.1.0 release: changelog, tag, verify published binaries and install instructions | 1 | SHA-215, SHA-267, SHA-269 |

## Epic 8: Later (SHA-193)

Not scheduled. Nice-to-haves and deferred decisions. No estimates.

| Ticket | Title |
|--------|-------|
| SHA-195 | Later: delete deactivated AWS keys after a retention period |
| SHA-196 | Later: self-rotation using the leaked credential as operator credential |
| SHA-198 | Later: GitHub Action wrapper and webhook trigger |
| SHA-199 | Later: more consumers (Kubernetes secrets, Vault, Doppler, dotenv files) |
| SHA-201 | Later: more providers (GCP service account keys, Slack, Stripe) |
| SHA-202 | Later: Betterleaks and GitHub secret-scanning alert input formats |
| SHA-204 | Later: mlock and core-dump protection for secret buffers |
| SHA-206 | Later: notifications on completion or failure (Slack, email) |
| SHA-208 | Later: Windows support |
| SHA-273 | Later: license allowlist decision for MPL-2.0 and ring before adding reqwest (blocked by SHA-212, blocks SHA-221) |

## Totals

| Epic | Tickets | Points |
|------|---------|--------|
| 1 Scaffolding | 5 | 6 |
| 2 Secret core | 6 | 11 |
| 3 Engine | 13 | 27 |
| 4 AWS | 4 | 10 |
| 5 GitHub and MVP | 4 | 9 |
| 6 npm and OpenAI | 3 | 6 |
| 7 Hardening and release | 4 | 7 |
| 8 Later | 9 | not estimated |
| MVP total | 39 | 76 |

## Critical path

SHA-194 → SHA-212 → SHA-216 → SHA-217 → SHA-221 → SHA-248 → SHA-250 → SHA-254 →
SHA-256 → SHA-259 → SHA-264 → SHA-267 → SHA-271.

Tickets off the critical path that can run in parallel once their blockers
are done: SHA-213, SHA-214, SHA-215, SHA-218, SHA-219, SHA-220, SHA-222,
SHA-223, SHA-246, SHA-247, SHA-249, SHA-251, SHA-252, SHA-253, SHA-255,
SHA-257, SHA-258, SHA-260, SHA-261, SHA-262, SHA-263, SHA-265, SHA-266,
SHA-268, SHA-269, SHA-270.
