Linear: https://linear.app/shakooky/issue/SHA-

## What

<!-- What changed and why, in a few bullets. -->

## Ticket edits

<!-- Changes to the ticket's scope, ACs or T-cases, or "none". -->

## T-cases

| T | Test |
|---|------|
| T1 | |

Plan: `docs/plans/SHA-.md`

## Checklist

- [ ] The Linear ticket is linked above and the branch is named `sha-<n>-<slug>`.
- [ ] Every T-case in the ticket has a test, listed in the table.
- [ ] No secret values, and no realistic secret-shaped literals, in tests, fixtures, snapshots, docs or output. Placeholders or generated canaries only.
- [ ] A change that touches secret values includes a test proving the value never reaches stdout, stderr, logs or the audit log.
- [ ] `rotate plan` still makes zero state-changing calls, and revoke is still the last step.
- [ ] `cargo fmt`, `cargo clippy`, `cargo test` and `cargo deny check` pass locally.
- [ ] Docs updated (README, CONTRIBUTING, `docs/`) where behaviour changed.
