# rotate.yaml reference

Every field of `rotate.yaml`, with its type, default and an example. The
structs behind it are in `src/config.rs`; `tests/user_docs.rs` fails when a
field is added there without a section here.

## Where rotate looks

rotate reads, in this order of preference:

1. the file named by `--config <PATH>`;
2. the file named by the `ROTATE_CONFIG` environment variable;
3. `rotate.yaml` in the working directory, if it exists.

The file is optional: without one every default applies, and rotate
searches no consumers. An empty file, or one holding only comments, is
valid. A file named by `--config` or `ROTATE_CONFIG` must exist.

Unknown keys and malformed values are errors that name the file, the
field and the line (`.../rotate.yaml: overlap_window at line 1, column 17:
invalid duration ...`), and exit 2 before anything else runs.

**Never put a credential in this file.** Provider credentials are read from
the environment; the file only names where to look.

## Precedence and environment variables

`overlap_window`, `audit_log` and `state_file` resolve as: command-line
flag, then environment variable, then `rotate.yaml`, then the default. An
empty environment variable counts as unset. Relative paths are relative to
the working directory.

| Setting | Flag | Environment variable |
| --- | --- | --- |
| config file | `--config` | `ROTATE_CONFIG` |
| `overlap_window` | `--overlap` | `ROTATE_OVERLAP` |
| `audit_log` | `--audit-log` | `ROTATE_AUDIT_LOG` |
| `state_file` | `--state-file` | `ROTATE_STATE_FILE` |

Other environment variables rotate reads:

| Variable | Used for |
| --- | --- |
| `ROTATE_ACTOR` | The actor recorded in the audit log. Default `user@hostname`. |
| `ROTATE_GITHUB_TOKEN`, then `GITHUB_TOKEN` | Operator token for GitHub Actions secrets. |
| `ROTATE_NPM_TOKEN`, then `NPM_TOKEN` | Operator token for npm (an `npm login` session token). |
| `OPENAI_ADMIN_KEY` | OpenAI Admin API key; the name is set by `providers.openai.admin_key_env`. |
| `AWS_*` | The standard AWS credential chain and region. |

What each credential needs is in [permissions.md](permissions.md).

## Name conventions

GitHub Actions secret values cannot be read back, so Actions secrets are
matched by name. For each provider rotate checks the convention names
below, plus the names you add under
`consumers.github_actions.secret_names` and `key_id_names`, in every repo
and org listed in `consumers.github_actions.targets`.

| Provider | Secret names (the token or secret half) | Key id names |
| --- | --- | --- |
| `aws` | `AWS_SECRET_ACCESS_KEY` | `AWS_ACCESS_KEY_ID` |
| `github` | `GH_TOKEN`, `GH_PAT` | none |
| `npm` | `NPM_TOKEN` | none |
| `openai` | `OPENAI_API_KEY` | none |

`GITHUB_TOKEN` is not a convention name: GitHub rejects Actions secret
names that start with `GITHUB_`. (It is still read as the operator token,
above.)

AWS Secrets Manager entries are matched by value instead: rotate reads each
entry listed under `consumers.aws_secrets_manager` and compares its value
(the whole value, or the top-level JSON string fields) with the leaked
secret.

## Complete example

Every field set. `tests/user_docs.rs` parses this block, so it is always
valid.

<!-- full-config -->
```yaml
overlap_window: 30m
audit_log: .rotate/audit.jsonl
state_file: .rotate/state.json
consumers:
  github_actions:
    targets: [acme/api, org:acme]
    secret_names:
      github: [RELEASE_TOKEN]
      aws: [CI_AWS_SECRET_ACCESS_KEY]
    key_id_names:
      aws: [CI_AWS_ACCESS_KEY_ID]
  aws_secrets_manager:
    secrets: [prod/api]
    tag_filters:
      - key: team
        values: [payments]
    json_keys: [AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY]
providers:
  aws:
    region: us-east-1
    endpoint_url: http://localhost:4566
  github:
    api_url: https://github.example.com/api/v3
  npm:
    registry: https://npm.example.com
  openai:
    admin_key_env: ROTATE_OPENAI_ADMIN_KEY
    api_url: https://openai-proxy.example.com
    allow_broader_replacement: true
```

[rotate.example.yaml](rotate.example.yaml) is the same file with a comment
on every field.

## Fields

### `overlap_window`

Type: duration, one or more `<integer><unit>` groups with units `s`, `m`,
`h`, `d` (`0s`, `90m`, `1h30m`, `7d`).
Default: `0s` (revoke as soon as the replacement is verified).

How long the old secret stays valid after every consumer is updated. With
a window above zero, `rotate apply` records a pending revoke and exits 3;
re-run it after the window, or pass `--wait`. See
[usage.md](usage.md#5-overlap-window).

```yaml
overlap_window: 1h30m
```

### `audit_log`

Type: path.
Default: `.rotate/audit.jsonl`

The append-only audit log. Created with mode 0600 in a 0700 directory. See
[security.md](security.md#the-audit-log).

### `state_file`

Type: path.
Default: `.rotate/state.json`

In-progress rotation state, used by resume, `status` and `rollback`. Keep
it for as long as a rotation might need a rollback: rollback without it is
not supported.

### `consumers.github_actions.targets`

Type: list of `owner/repo` or `org:<name>`.
Default: none (`[]`): no Actions secret is searched.

Repositories and organizations whose Actions secrets are checked. Needs
an operator token in `ROTATE_GITHUB_TOKEN` (or `GITHUB_TOKEN`) that can read
and write Actions secrets; see [permissions.md](permissions.md).

```yaml
consumers:
  github_actions:
    targets: [acme/api, org:acme]
```

### `consumers.github_actions.secret_names`

Type: map of provider (`aws`, `github`, `npm`, `openai`) to a list of
secret names.
Default: none (`{}`): only the convention names.

Extra Actions secret names that hold the token, or the secret half of an
AWS key pair, added to the provider's convention.

```yaml
consumers:
  github_actions:
    secret_names:
      github: [RELEASE_TOKEN]
```

### `consumers.github_actions.key_id_names`

Type: map of provider to a list of secret names.
Default: none (`{}`): only `AWS_ACCESS_KEY_ID`.

Extra Actions secret names that hold the access key id half of an AWS key
pair, so both halves are written together.

```yaml
consumers:
  github_actions:
    key_id_names:
      aws: [CI_AWS_ACCESS_KEY_ID]
```

### `consumers.aws_secrets_manager.secrets`

Type: list of secret names or ARNs.
Default: none (`[]`).

Secrets Manager entries whose values are compared with the leaked secret.
Uses the operator's AWS credentials.

```yaml
consumers:
  aws_secrets_manager:
    secrets: [prod/api]
```

### `consumers.aws_secrets_manager.tag_filters`

Type: list of `{key, values}`.
Default: none (`[]`).

Entries selected by tag, in addition to `secrets`. Needs
`secretsmanager:ListSecrets`.

### `consumers.aws_secrets_manager.tag_filters[].key`

Type: string.
Default: none; required in every filter.

The tag key.

### `consumers.aws_secrets_manager.tag_filters[].values`

Type: list of strings.
Default: none (`[]`): any value of the tag matches.

Accepted tag values.

```yaml
consumers:
  aws_secrets_manager:
    tag_filters:
      - key: team
        values: [payments]
```

### `consumers.aws_secrets_manager.json_keys`

Type: list of strings.
Default: unset: every top-level string value of a JSON secret is compared.

For JSON secrets, the keys to compare and update. Other keys are kept as
they are, and an AWS pair stored as two keys is updated in one new version.

```yaml
consumers:
  aws_secrets_manager:
    json_keys: [AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY]
```

### `providers.aws.region`

Type: string.
Default: unset: the AWS environment decides (`AWS_REGION`, the profile).

Region for IAM, STS and Secrets Manager calls.

### `providers.aws.endpoint_url`

Type: URL (`https://` or `http://`).
Default: unset: AWS's own endpoints.

Sends STS, IAM and Secrets Manager calls to this URL instead, for
LocalStack or a test server.

### `providers.github.api_url`

Type: URL.
Default: `https://api.github.com`

GitHub REST API base URL, used by the GitHub provider and the Actions
consumer. Change it for GitHub Enterprise Server.

### `providers.npm.registry`

Type: URL.
Default: `https://registry.npmjs.org`

npm registry base URL.

### `providers.openai.admin_key_env`

Type: environment variable name.
Default: `OPENAI_ADMIN_KEY`

The variable that holds the OpenAI Admin API key. It names a variable; it
never holds the key. Without the key the OpenAI provider runs in manual
mode: it checks keys, asks for the replacement and cannot revoke. See
[providers.md](providers.md).

### `providers.openai.api_url`

Type: URL, without `/v1`.
Default: `https://api.openai.com`

OpenAI API base URL.

### `providers.openai.allow_broader_replacement`

Type: boolean.
Default: `false`

With an Admin API key, rotate can create the replacement itself as a project
service-account key, but that key gets all permissions: the Admin API cannot
read or copy the leaked key's restrictions. By default rotate therefore uses
manual mode for OpenAI and asks you to create a restricted key and paste it.
Set this to `true` (or pass `--allow-broader-replacement` to `plan` or
`apply`) to let rotate create the broader key; the plan then shows a
`scope widening` note and the audit log records `scope_widened: true`. See
[permissions.md](permissions.md).
