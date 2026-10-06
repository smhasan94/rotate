# Test fixtures

Every credential in this directory is fake and must stay fake. Never paste
output from a scan of a real repository here.

- AWS keys are the examples from AWS's own documentation
  (`AKIAIOSFODNN7EXAMPLE`, `AKIAI44QH8DHBEXAMPLE` and their secret halves).
- Other tokens contain `FAKE` and do not carry a valid provider checksum, so
  GitHub push protection and secret scanners do not treat them as real.
- `trufflehog_aws_e2e.ndjson` (SHA-264) holds `@KEY_ID@` and `@SECRET@`
  placeholders that `tests/e2e_aws.rs` fills with values built at runtime.
  The end-to-end test needs a key id that is not a documentation example
  (those are reported invalid without any call), and committing one would
  trip secret scanners.
- `github_alerts.json` (SHA-337) is an array of GitHub REST
  secret-scanning alerts: GitHub, npm and OpenAI tokens, an AWS secret key
  alert with its key id alert at the same path and commit, a second key id
  alert elsewhere, a resolved alert, a base64-encoded alert, a
  webhook-shaped alert without `secret`, and an unsupported
  `github_ssh_private_key` alert whose value is not a key.
- `trufflehog_malformed.ndjson` line 2 is deliberately truncated JSON. Its
  text is a canary that tests assert never appears in warnings or logs.

The record shapes match TruffleHog 3.97.9 (`filesystem` and `git` sources)
and gitleaks 8.30.1 (`dir -f json`). `trufflehog_aws_legacy.ndjson` has no
`SecretParts`, as written by TruffleHog versions before that field existed.
See `docs/report-formats.md` for the field mapping.
