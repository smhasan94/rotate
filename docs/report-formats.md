# Report formats

`rotate` reads scanner reports and turns each entry into a finding: the
secret value (held only in zeroized memory), the scanner's detector or rule
name, and where it was found. The format is detected from the first byte
that is not whitespace: `[` is gitleaks, `{` is TruffleHog. A forced format
that does not match the content is an error naming both.

Tested with TruffleHog 3.97.9 and gitleaks 8.30.1.

## TruffleHog

Produce with `trufflehog <source> --json`. One JSON object per line.

| Finding field | TruffleHog field |
|---|---|
| secret | `Raw`, except AWS (below) |
| detector | `DetectorName` |
| file, line, commit | `SourceMetadata.Data.<source kind>.file`, `.line`, `.commit` |
| `extra.access_key_id` | AWS only: `SecretParts.access_key_id`, else `Raw` |
| `extra.is_canary` | `"true"` when `ExtraData.is_canary` is `"true"` |

For AWS, `Raw` is the access key id, not the secret. The secret access key
comes from `SecretParts.secret_access_key`. On TruffleHog versions without
`SecretParts`, it comes from `RawV2` (`<key id>:<secret>`, with or without
the colon). An AWS entry without both halves is skipped.

`is_canary` marks keys from canarytokens.org. Any API call made with one,
including a validity check, alerts whoever planted it.

## gitleaks

Produce with `gitleaks git -f json -r report.json` or `gitleaks dir ...`. One
JSON array.

| Finding field | gitleaks field |
|---|---|
| secret | `Secret` |
| detector | `RuleID` |
| file, line, commit | `File`, `StartLine`, `Commit` (empty means none) |

`Match` is not read: it holds the secret plus surrounding text.

gitleaks reports an AWS access key id (`aws-access-token`) and its secret
access key (`generic-api-key`) as two separate findings, so a gitleaks AWS
finding holds only the key id and cannot be rotated from the report alone.
Use a TruffleHog report or `rotate plan --stdin` with `KEY_ID:SECRET`.

## Skipped entries

An entry that is not valid JSON, has a field of the wrong type, or has no
secret is skipped. A warning names the format, the line, and a fixed reason
with the column. Warnings never include the entry's text, because the text
may contain the secret. A gitleaks file that is not a JSON array at all is
an error, reported by line and column only.

## Memory handling

The report file is read into a buffer that is wiped on drop, and each secret
is copied straight into a `SecretValue`. One known gap: a JSON string with
escape sequences is decoded through serde_json's own scratch buffer, which
is not wiped. The token formats of the four MVP providers contain no
characters that the scanners escape.
