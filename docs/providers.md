# Provider and consumer matrix

What rotate does for each provider and consumer, operation by operation,
and what you have to do yourself. Read this before an incident: some
providers need a token pasted by hand, some cannot be rolled back, and some
need an operator credential that takes time to get.

`rotate plan` prints a pointer to this page whenever a rotation has a manual
step or a consumer it cannot update. The exact operator permissions are in
[permissions.md](permissions.md).

Every status is one of:

- **Automated**: rotate does it through the provider's API.
- **Manual**: rotate cannot do it, tells you what to do by hand, and carries
  on (or stops safely) around it.
- **Unsupported**: nobody can do it, or rotate does not attempt it.

A cell like `Automated; Manual without admin key` means the status depends
on whether that operator credential is set.

The operations are the methods of the `Provider` trait in
`src/provider/mod.rs`. Each table below is headed by the provider's `name`,
and its `replacement_mode` decides whether `create_replacement` is Automated
or Manual.

| Operation | Used by | What it does |
| --- | --- | --- |
| `identify` | plan | Recognises the secret's format. No network. |
| `check_valid` | plan | The cheapest read-only call that says valid, invalid or unknown. |
| `describe_scope` | plan | Who owns the secret and what it can reach. |
| `create_replacement` | apply | Mints the new secret. In manual mode, `manual_instructions` says what to create and apply asks you to paste it instead. When `scope_widening` returns a note, an automatic replacement would be broader than the leaked secret: the plan shows the note and the `create` audit entry records `scope_widened`. |
| `verify` | apply | Checks the new secret works and belongs to the same identity, before anything is revoked. |
| `verify_replacement` | apply (resume) | Checks the replacement by its reference when apply resumes at verify in a new process, since rotate never stores the value. |
| `revoke` | apply | Revokes the leaked secret. Always the last step. When `manual_revoke` returns a row, the plan shows it instead and apply stops at revoke. When `revoke_blocker` returns a reason (npm without a usable operator token), the plan shows it as a blocker. |
| `revoke_replacement` | rollback | Revokes the replacement by its reference. |
| `restore` | rollback | Brings the revoked secret back. |

## Providers

### AWS IAM access keys (`aws`)

| Operation | Status | Operator credential | Note |
| --- | --- | --- | --- |
| `identify` | Automated | none | `AKIA` key id plus a 40-character secret. `ASIA` temporary keys are identified but reported unknown: revoke them by rotating their source. |
| `check_valid` | Automated | none | `sts:GetCallerIdentity` signed with the leaked key, the only call it ever signs. It needs no permission. |
| `describe_scope` | Automated | AWS credentials | Owner ARN, last use, attached, inline and group policies, and key slots. Without operator credentials the plan shows the scope as unavailable. |
| `create_replacement` | Automated | AWS credentials | `iam:CreateAccessKey` for the same user. Refused when the user already has two keys: delete the key that is not leaked yourself. |
| `verify` | Automated | none | `sts:GetCallerIdentity` signed with the new key; its ARN must match. Retried while IAM propagates the key. |
| `verify_replacement` | Automated | AWS credentials | The replacement key id must belong to the same IAM user and be Active (`iam:GetAccessKeyLastUsed`, `iam:ListAccessKeys`). |
| `revoke` | Automated | AWS credentials | `iam:UpdateAccessKey Status=Inactive`. The key is deactivated, never deleted. |
| `revoke_replacement` | Automated | AWS credentials | Deactivates the replacement key by its id. Nothing is deleted. |
| `restore` | Automated | AWS credentials | Reactivates the old key, then deactivates the replacement. |

### GitHub tokens (`github`)

| Operation | Status | Operator credential | Note |
| --- | --- | --- | --- |
| `identify` | Automated | none | `ghp_`, `github_pat_`, `gho_`, `ghu_`, `ghs_` and `ghr_` prefixes; a legacy 40-hex token only with a GitHub detector hint. |
| `check_valid` | Automated | none | `GET /user` signed with the leaked token (`ghs_`: `GET /installation/repositories`). A `ghr_` refresh token cannot be checked and is reported unknown. |
| `describe_scope` | Automated | none | Login, token type, classic scopes, expiry and orgs, read with the leaked token. Fine-grained permissions are not readable through the API. |
| `create_replacement` | Manual | none | GitHub has no API to create tokens. Apply names the page and, for a classic token, the scopes, then asks you to paste the new token. |
| `verify` | Automated | none | `GET /user` with the pasted token; the login must match. |
| `verify_replacement` | Unsupported | none | A pasted token is never stored. A rotation that stopped before verify is marked `needs_rollback`. |
| `revoke` | Automated | none | `POST /credentials/revoke`, unauthenticated. `ghs_` installation tokens and legacy 40-hex tokens are not accepted by that API and are never revoked; `ghs_` tokens expire within an hour. |
| `revoke_replacement` | Manual | none | Rollback cannot revoke a pasted token and tells you to revoke it on GitHub by hand. |
| `restore` | Unsupported | none | GitHub cannot reactivate a revoked token. Rollback restores consumers only. |

### npm access tokens (`npm`)

The npm operator token must be an `npm login` session token for the same
account as the leaked token: npm's token list accepts no other kind,
granular access tokens included. Session tokens last two hours, so an
unattended run needs a fresh `npm login` first; without a usable one the
plan shows a revoke blocker naming `ROTATE_NPM_TOKEN`.

| Operation | Status | Operator credential | Note |
| --- | --- | --- | --- |
| `identify` | Automated | none | `npm_` plus 36 letters and digits (granular and `npm login` session tokens). |
| `check_valid` | Automated | none | `GET /-/whoami` signed with the leaked token. |
| `describe_scope` | Automated | npm session token | The user from `whoami`, then the token's entry in your token list. The list needs an `npm login` session token; without one the plan says "token not visible to operator account". |
| `create_replacement` | Manual | none | npm creates tokens only with the account password and a one-time password. Apply names the granular token page and the settings to copy, then asks you to paste it. |
| `verify` | Automated | none | `GET /-/whoami` with the pasted token; the user must match. |
| `verify_replacement` | Unsupported | none | A pasted token is never stored. A rotation that stopped before verify is marked `needs_rollback`. |
| `revoke` | Automated | npm session token | Deletes the token by the id in your token list, so it needs the list and a session token; a granular token cannot list. An account that asks for a one-time password, or a granular token with 2FA bypass (403), makes the delete fail; rotate names the page to delete it on. |
| `revoke_replacement` | Manual | npm session token | A pasted replacement has no token id, so rollback tells you to delete it by hand. |
| `restore` | Unsupported | none | npm cannot bring back a deleted token. Rollback restores consumers only. |

### OpenAI API keys (`openai`)

| Operation | Status | Operator credential | Note |
| --- | --- | --- | --- |
| `identify` | Automated | none | `sk-proj-`, `sk-svcacct-`, legacy `sk-` keys and `sk-admin-` admin keys. Admin keys are identified so they are not claimed by another provider. |
| `check_valid` | Automated | none | `GET /v1/models` signed with the leaked key. Admin keys cannot call it: they are reported unknown and never rotated. |
| `describe_scope` | Automated | OpenAI admin key | With an admin key, the project, key name, owner and last use from the Admin API. Without one, only the organization from the response header. |
| `create_replacement` | Automated; Manual without admin key or opt-in | OpenAI admin key | Manual by default: apply names the project and the leaked key and asks you to paste a new key with Restricted permissions matching it. With an admin key and the opt-in (`providers.openai.allow_broader_replacement: true` or `--allow-broader-replacement`), a new service account in the same project, named `rotate-<fingerprint>`. It gets all permissions in the project, which may be broader than the leaked key, so the plan shows a `scope widening` note and the audit log records `scope_widened: true`. |
| `verify` | Automated | OpenAI admin key | `GET /v1/models` with the new key, which must be listed in the same project. Without an admin key only the organization header is compared. |
| `verify_replacement` | Unsupported | none | Not implemented for OpenAI. A rotation that stopped before verify is marked `needs_rollback`. |
| `revoke` | Automated; Manual without admin key | OpenAI admin key | Deletes a user-owned key by id, or a service-account key by deleting its service account when that is the account's only key. Otherwise, and without an admin key, the plan shows a manual revoke and apply stops at revoke. |
| `revoke_replacement` | Automated; Manual without admin key or opt-in | OpenAI admin key | Deletes the service account rotate created. A pasted replacement is revoked by hand. |
| `restore` | Unsupported | none | OpenAI cannot bring back a deleted key. Rollback restores consumers only. |

## Consumers

The operations are the methods of the `Consumer` trait in
`src/consumer/mod.rs`; each table is headed by the consumer's `name`. `find` matches either `ByValue` (the stored value's
fingerprint equals the secret's) or `ByName` (the value cannot be read back,
so the name decides). A match `find` marks not updatable is listed in the
plan with the reason and blocks revoke unless you pass `--force`.

### GitHub Actions secrets (`github-actions`)

Operator token: `ROTATE_GITHUB_TOKEN`, else `GITHUB_TOKEN`. Repository
secrets need a classic token with `repo`, or a fine-grained token with the
repository permission "Secrets: read and write". Organization secrets need a
classic token with `admin:org`, or a fine-grained token with the
organization permission "Secrets: read and write".

| Operation | Status | Permissions | Note |
| --- | --- | --- | --- |
| `find` | Automated | Secrets: read | ByName only: Actions values cannot be read back. Lists the secrets of each target in `consumers.github_actions.targets` and matches the provider's convention names and the `rotate.yaml` mapping. A 403 or 404 target becomes a not-updatable match. |
| `update` | Automated | Secrets: read and write | Seals the new value with the target's public key and writes it. Org secrets keep their visibility and selected repositories. A secret cannot hold both halves of an AWS key pair. |
| `restore` | Automated | Secrets: read and write | Writes the old value back the same way. Rollback takes the old value from the original report or stdin. |

### AWS Secrets Manager (`aws-secrets-manager`)

Operator credentials: the standard AWS chain, as for the AWS provider. An
entry encrypted with a customer managed KMS key also needs `kms:Decrypt` and
`kms:GenerateDataKey` on that key.

| Operation | Status | Permissions | Note |
| --- | --- | --- | --- |
| `find` | Automated | `secretsmanager:GetSecretValue`, `secretsmanager:ListSecrets` | ByValue: compares the fingerprint of a plain value or of a top-level JSON string field. `ListSecrets` is only for `tag_filters`. An entry rotate cannot read is listed ByName and not updatable. |
| `update` | Automated | `secretsmanager:GetSecretValue`, `secretsmanager:PutSecretValue` | Writes a new version with only the matched fields changed; an AWS key pair's key id field is updated in the same write. |
| `restore` | Automated | `secretsmanager:GetSecretValue`, `secretsmanager:PutSecretValue` | Writes the old value back as a new version. |

## Before an incident

### AWS

- [ ] Operator AWS credentials in the default chain with the actions in
  [permissions.md](permissions.md), scoped to the users rotate may touch.
- [ ] No IAM user that holds a rotatable key uses both key slots; rotate
  will not delete a key to make room.
- [ ] `providers.aws.region` set if your default region is not the keys'.

### GitHub

- [ ] Know where each token is created: classic and fine-grained token pages,
  or the OAuth or GitHub App that issued it. You will paste the replacement.
- [ ] For fine-grained tokens, note their permissions: rotate cannot read
  them.
- [ ] For `ghs_` installation tokens, know which app issued them: rotate does
  not revoke them.
- [ ] A GitHub token for the Actions consumer (see below), separate from any
  token that might leak.

### npm

- [ ] A way to get an `npm login` session token for each account whose
  tokens may leak, set as `ROTATE_NPM_TOKEN` (not the `NPM_TOKEN` your CI
  uses). It lasts two hours, so an unattended run cannot keep one: run
  `npm login` shortly before. A granular access token does not work.
- [ ] Know whether the account asks for a one-time password to delete
  tokens; if it does, plan to delete the leaked token on npmjs.com.
- [ ] Access to the account's website login and one-time password, to create
  the replacement granular token.

### OpenAI

- [ ] An organization Admin API key in `OPENAI_ADMIN_KEY` with read and write
  access to projects, kept separate from the keys it manages. Without it,
  replacement and revoke are manual.
- [ ] Decide whether rotate may replace keys with service-account keys that
  have all permissions in the project (`allow_broader_replacement`). If not,
  be ready to create restricted keys by hand on the API keys page.
- [ ] Know which leaked keys are service-account keys that share an account
  with other keys: rotate cannot revoke those.
- [ ] Admin keys themselves are rotated by hand on the admin keys page.

### Consumers

- [ ] `consumers.github_actions.targets` lists every repo and org whose
  secrets may hold a key, and the mapping in `rotate.yaml` covers names that
  do not follow the convention.
- [ ] `consumers.aws_secrets_manager` names or tags every entry that may
  hold a key.

## Known gaps

- AWS deactivates keys and never deletes them. Delete deactivated keys
  yourself when you no longer need rollback.
- GitHub `ghs_` installation tokens are not revocable through the credential
  revocation API. rotate checks and describes them but never revokes or
  replaces them.
- npm: deleting a token often needs a one-time password, which rotate does
  not send, and the token list accepts only an `npm login` session token.
- OpenAI: a service-account key is removed only by deleting its service
  account, and only when it is that account's only key. Admin keys are not
  rotated.
- Only AWS can resume at verify after the process exits; for the others the
  rotation is marked `needs_rollback`.
- Only AWS can restore a revoked secret. For the others, rollback puts the
  old value back in consumers but the old secret stays revoked.
