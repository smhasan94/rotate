# Report formats

`rotate` reads scanner reports and turns each entry into a finding: the
secret value (held only in zeroized memory), the scanner's detector or rule
name, and where it was found. The format is detected from the first byte
that is not whitespace: `[` is gitleaks, `{` is TruffleHog. A forced format
that does not match the content is an error naming both. GitHub
secret-scanning alerts are never detected; name them with
`--format github-alert`.

A report is a file (`rotate plan report.json`) or, with `--format`, a
document on stdin (`rotate plan --stdin --format trufflehog`). Without
`--format`, `--stdin` reads one secret instead. `--provider` cannot be
combined with `--stdin --format` (exit 2): a report names its own types.

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

## GitHub secret-scanning alerts

`--format github-alert` reads the alert objects that GitHub's REST API
returns: one alert from
`GET /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}`, an array
from the list endpoint, or several of either back to back. Pipe the
response straight in, so the value never sits in a shell variable or a
file:

```sh
gh api repos/acme/api/secret-scanning/alerts/42 \
  | rotate plan --stdin --format github-alert
```

The token needs "Secret scanning alerts: read" (a fine-grained personal
access token or a GitHub App installation token; classic tokens need
`repo` or `security_events`) and an administrator of the repository or
organization. The `GITHUB_TOKEN` of a GitHub Actions workflow cannot read
secret-scanning alerts. The `secret_scanning_alert` webhook payload has no
`secret` field, so it is not enough on its own: fetch the alert it names.

| Finding field | Alert field |
|---|---|
| secret | `secret`, base64-decoded when `is_base64_encoded` is `true` |
| detector | `secret_type` |
| file | `html_url`, the alert's page |
| line, commit | `first_location_detected.start_line`, `.commit_sha` |
| `extra.access_key_id` | AWS only: the paired `aws_access_key_id` alert's `secret` |

`number` and `state` are read to skip alerts. Other fields, including
`validity`, are not read: rotate checks validity itself. The `secret_type`
names the provider: `aws_access_key_id`, `aws_secret_access_key` (aws),
`github_personal_access_token`, `github_oauth_access_token`,
`github_app_installation_access_token` (github), `npm_access_token` (npm)
and `openai_api_key` (openai). Other types, such as `github_refresh_token`
or `github_ssh_private_key`, are shown as unsupported.

GitHub reports an AWS key pair as two alerts. An `aws_secret_access_key`
alert pairs with:

1. the `aws_access_key_id` alert whose `first_location_detected` has the
   same `path` and `commit_sha`; otherwise
2. the only open `aws_access_key_id` alert in the input, when no other
   secret-key alert is left to pair with it and no alert at its own place
   took it; otherwise
3. nothing: the secret is `not rotatable`, and the note says to use
   `rotate plan --stdin` with `KEY_ID:SECRET`.

rotate never tries a candidate key id against AWS to find the pair. A
key-id alert that pairs with nothing is `not rotatable` too.

Alerts skipped with a warning naming the alert number:

- `state` is `resolved`;
- no `secret` field, or an empty one (the webhook payload, or the REST API
  with `hide_secret=true`);
- `is_base64_encoded` is `true` but the value does not decode.

The base64 value is decoded into a new buffer that is wiped on drop. A
document that is not valid JSON, or holds a value that is neither an alert
object nor an array, is refused (exit 2) by line and column only.

## Skipped entries

An entry that is not valid JSON, has a field of the wrong type, or has no
secret is skipped. A warning names the format, the line, and a fixed reason
with the column. Warnings never include the entry's text, because the text
may contain the secret. A gitleaks file that is not a JSON array at all is
an error, reported by line and column only. GitHub alert documents follow
the same rules and add the alert skips above.

## Memory handling

The report file, or the document on stdin, is read into a buffer that is
wiped on drop (one that grows is copied into a larger wiped buffer, never
reallocated in place), and each secret is copied straight into a
`SecretValue`. One known gap: a JSON string with
escape sequences is decoded through serde_json's own scratch buffer, which
is not wiped. The token formats of the four MVP providers contain no
characters that the scanners escape.

## After parsing

`rotate plan` assesses the findings (SHA-248):

- Findings with the same secret are merged into one row, listing every
  place it was found. When one of them carries an AWS access key id (a
  TruffleHog `AWS` finding), that one is used, so a gitleaks
  `generic-api-key` finding for the same secret becomes an AWS rotation.
- The provider comes from the scanner's detector or rule name first, then
  from the shape of the value. When the two disagree, the detector wins and
  a warning names both.
- Each supported secret is checked with a read-only call, at most
  `--concurrency` (default 8) at a time, with up to three attempts on rate
  limits and server errors. A check that keeps failing shows as `unknown`
  with the reason; it does not stop the run.
- Gitleaks AWS key-id-only findings, unpaired GitHub AWS alerts and canary
  keys are `not rotatable` and are never sent to the provider.

Every row is shown, with reasons listed under the table. `--json` prints
the same data as an array.
