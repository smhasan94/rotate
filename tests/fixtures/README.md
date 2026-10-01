# Test fixtures

Every credential in this directory is fake and must stay fake. Never paste
output from a scan of a real repository here.

- AWS keys are the examples from AWS's own documentation
  (`AKIAIOSFODNN7EXAMPLE`, `AKIAI44QH8DHBEXAMPLE` and their secret halves).
- Other tokens contain `FAKE` and do not carry a valid provider checksum, so
  GitHub push protection and secret scanners do not treat them as real.
- `trufflehog_malformed.ndjson` line 2 is deliberately truncated JSON. Its
  text is a canary that tests assert never appears in warnings or logs.

The record shapes match TruffleHog 3.97.9 (`filesystem` and `git` sources)
and gitleaks 8.30.1 (`dir -f json`). `trufflehog_aws_legacy.ndjson` has no
`SecretParts`, as written by TruffleHog versions before that field existed.
See `docs/report-formats.md` for the field mapping.
