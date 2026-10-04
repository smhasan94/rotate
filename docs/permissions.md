# Operator permissions

rotate never uses a leaked secret as its own credential (decision D3). It
acts with the operator's credentials, so scope those to what rotate needs.
Running it with admin credentials during an incident widens the blast
radius if rotate or the host is compromised. This page lists the minimum
for each provider and consumer, derived from the calls the code makes.
What rotate automates per provider, and what stays manual, is in
[providers.md](providers.md).

## By command

| Command | AWS (operator credentials) | GitHub Actions token | npm operator token | OpenAI admin key |
| --- | --- | --- | --- | --- |
| `rotate plan` | the IAM reads below, `secretsmanager:GetSecretValue`, `secretsmanager:ListSecrets` (tag filters only) | Secrets: read | token list | project and key reads |
| `rotate plan --check-permissions` | as `plan`, plus `sts:GetCallerIdentity` and `iam:SimulatePrincipalPolicy` | as `plan`, plus the public-key read | as `plan` | as `plan` |
| `rotate apply` | as `plan`, plus `iam:CreateAccessKey`, `iam:UpdateAccessKey`, `secretsmanager:PutSecretValue` | Secrets: read and write | token list and delete | as `plan`, plus service account create and key or service account delete |
| `rotate rollback` | `iam:GetAccessKeyLastUsed`, `iam:UpdateAccessKey`, `secretsmanager:GetSecretValue`, `secretsmanager:PutSecretValue` | Secrets: read and write | none | service account delete |
| `rotate status` | none | none | none | none |

`rotate status` reads only the local state file and audit log and makes no
network call. `rotate apply` re-plans first, so it needs everything `plan`
needs.

## Checking permissions before apply (`--check-permissions`)

`rotate plan --check-permissions` probes your own permissions, read-only,
after building the plan, so a missing permission shows up before `rotate
apply` rather than halfway through it.

- AWS: rotate calls `sts:GetCallerIdentity` with your credentials to learn
  your principal ARN (an assumed-role session is checked as its role), then
  `iam:SimulatePrincipalPolicy` with the provider's IAM actions on the key
  owner's ARN, and with `secretsmanager:GetSecretValue` and
  `secretsmanager:PutSecretValue` on each matched entry that `rotate.yaml`
  names by ARN. Each action the simulation does not allow becomes a plan
  blocker: `operator lacks iam:CreateAccessKey on arn:aws:iam::...:user/...
  (IAM policy simulation)`. An entry named by name is not simulated (its
  ARN has a suffix rotate does not know); list it by ARN to check it.
- GitHub Actions: rotate reads `GET /repos/{owner}/{repo}/actions/secrets/public-key`
  (or `/orgs/{org}/...`) once per target with an updatable match; every
  write starts with this call. A 403 or 404, or a classic token whose
  `x-oauth-scopes` lacks `repo` (repository) or `admin:org` (org), marks
  the target's matches not updatable with the reason
  `token lacks Secrets: write`, which also adds the usual "consumer cannot
  be updated" blocker.
  GitHub does not expose a fine-grained token's permissions, so a
  fine-grained token that can read the key passes with a warning: make sure
  it has "Secrets: read and write".
- npm and OpenAI have no read-only way to test a permission, so they are
  not probed. Their plan rows already show what the operator credential
  could not see.

A probe that cannot run (no `iam:SimulatePrincipalPolicy`, no operator
credentials, a network error) prints a warning on stderr and adds nothing to
the plan. The probes never change state, and `--json` keeps the same shape:
the results are in `blockers` and in each consumer's `reason`.
`iam:SimulatePrincipalPolicy` and `sts:GetCallerIdentity` are needed only
for this flag.

## AWS IAM access keys (provider `aws`)

The leaked key signs one call only: `sts:GetCallerIdentity`, the validity
check in `rotate plan`. That call needs no permission. The replacement key
signs the same call during apply, to verify it.

Everything else uses the operator's AWS credentials from the default chain
(environment, shared profile, SSO or credential process), in the region from
`providers.aws.region`, else `AWS_REGION` / `AWS_DEFAULT_REGION`, else the
profile, else `us-east-1`. Without operator credentials `rotate plan` still
reports validity and shows the scope as unavailable.

| Action | Used by | Why |
| --- | --- | --- |
| `iam:GetAccessKeyLastUsed` | plan, apply, rollback | owner of the leaked key (or of the replacement, on rollback and resume) and when each key was last used |
| `iam:GetUser` | plan, apply | the owner's ARN, which the replacement must match |
| `iam:ListAttachedUserPolicies`, `iam:ListUserPolicies`, `iam:ListGroupsForUser` | plan, apply | scope lines; a denied read becomes a "not visible" line |
| `iam:ListAccessKeys` | plan, apply | key slots: IAM allows two keys per user; on resume, that the replacement is still Active |
| `iam:CreateAccessKey` | apply | the replacement key |
| `iam:UpdateAccessKey` | apply, rollback | deactivate the leaked key; on rollback reactivate it and deactivate the replacement |
| `sts:GetCallerIdentity` | plan `--check-permissions` | your own ARN, for the simulation; needs no permission |
| `iam:SimulatePrincipalPolicy` | plan `--check-permissions` | the permission probe |

rotate never calls `iam:DeleteAccessKey`, and the policy below does not
grant it. When the user already has two keys, the plan shows a warning and
apply refuses to create a replacement: delete the key that is not leaked
yourself, then run apply again. Deactivated keys are never deleted either;
delete them yourself once you no longer need rollback.

### Minimal IAM policy

Attach this to the principal you run rotate as. It covers the AWS provider
and the Secrets Manager consumer; drop the statements for the parts you do
not use. Replace `<account-id>`, `<region>` and `<operator>` (the user or
role you run rotate as).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RotateIamAccessKeys",
      "Effect": "Allow",
      "Action": [
        "iam:GetAccessKeyLastUsed",
        "iam:GetUser",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "iam:ListGroupsForUser",
        "iam:ListAccessKeys",
        "iam:CreateAccessKey",
        "iam:UpdateAccessKey"
      ],
      "Resource": "arn:aws:iam::<account-id>:user/*"
    },
    {
      "Sid": "RotateSecretsManagerEntries",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:PutSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:<region>:<account-id>:secret:*"
    },
    {
      "Sid": "RotateSecretsManagerTagSearch",
      "Effect": "Allow",
      "Action": "secretsmanager:ListSecrets",
      "Resource": "*"
    },
    {
      "Sid": "RotateCheckPermissions",
      "Effect": "Allow",
      "Action": "iam:SimulatePrincipalPolicy",
      "Resource": "arn:aws:iam::<account-id>:<operator>"
    },
    {
      "Sid": "RotateWhoAmI",
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    }
  ]
}
```

`RotateSecretsManagerTagSearch` is needed only with
`consumers.aws_secrets_manager.tag_filters`; `ListSecrets` does not support
resource-level permissions. `RotateCheckPermissions` and `RotateWhoAmI` are
needed only for `--check-permissions`; `sts:GetCallerIdentity` is allowed
for every principal anyway, so that statement just makes it explicit.

### Scoping the policy

Narrow each `Resource` to what rotate may touch:

| To limit rotate to | Use |
| --- | --- |
| IAM users under a path, for example CI users | `arn:aws:iam::<account-id>:user/ci/*` |
| named IAM users | `arn:aws:iam::<account-id>:user/deploy-bot`, one entry per user |
| Secrets Manager entries under a prefix | `arn:aws:secretsmanager:<region>:<account-id>:secret:prod/*` |
| one Secrets Manager entry | `arn:aws:secretsmanager:<region>:<account-id>:secret:prod/app-*` (the `-*` matches the 6-character suffix AWS adds) |
| simulating only yourself | `arn:aws:iam::<account-id>:user/<your-user>` or `arn:aws:iam::<account-id>:role/<your-role>` |

You can also add conditions, for example `aws:ResourceTag/rotate` on IAM
users, or `secretsmanager:ResourceTag/...` on entries. An entry encrypted
with a customer managed KMS key also needs `kms:Decrypt` (read) and
`kms:GenerateDataKey` (write) on that key; the AWS managed key needs
nothing extra.

## AWS Secrets Manager (consumer `aws-secrets-manager`)

Uses the same operator AWS credentials and region chain as the AWS
provider.

| Action | Used by | Why |
| --- | --- | --- |
| `secretsmanager:GetSecretValue` | plan, apply, rollback | compare the stored value's fingerprint; read the current version before writing |
| `secretsmanager:PutSecretValue` | apply, rollback | write the new value (rollback: the old value) as a new version |
| `secretsmanager:ListSecrets` | plan, apply | only for `tag_filters` |

An entry rotate cannot read is listed by name and marked not updatable.

## GitHub Actions secrets (consumer `github-actions`)

The operator token comes from `ROTATE_GITHUB_TOKEN`, else `GITHUB_TOKEN`.
Use a token other than any you might be rotating, and set
`ROTATE_GITHUB_TOKEN` in CI so the job's own `GITHUB_TOKEN` is not used.

| Target | Classic token | Fine-grained token |
| --- | --- | --- |
| repository secrets | `repo` scope | repository permission "Secrets: read and write" on each target repository |
| organization secrets | `admin:org` scope | organization permission "Secrets: read and write" (shown as "Organization secrets" in some GitHub versions) |

| Call | Used by | Why |
| --- | --- | --- |
| `GET {target}/actions/secrets` | plan, apply | list secret names (values cannot be read back); a 403 or 404 makes the target not updatable |
| `GET {target}/actions/secrets/public-key` | apply, rollback, plan `--check-permissions` | the key every value is sealed with; the write probe |
| `GET /orgs/{org}/actions/secrets/{name}` and `.../repositories` | apply, rollback | keep an org secret's visibility and selected repositories |
| `PUT {target}/actions/secrets/{name}` | apply, rollback | write the sealed value |

A fine-grained token with only "Secrets: read" can plan but not apply:
the `PUT` fails, apply stops before revoke and the old secret stays valid.

## GitHub tokens (provider `github`)

The GitHub provider needs no operator token. GitHub has no API that reads
a token's owner or scopes with another credential, so the leaked token
signs the read-only calls of `rotate plan`; it never signs a call that
changes state.

| Call | Signed with | Used by | Why |
| --- | --- | --- | --- |
| `GET /user` | leaked token | plan | validity (200 valid, 401 invalid), login, classic scopes from `x-oauth-scopes`, expiry |
| `GET /user/orgs` | leaked token | plan | org memberships; a denied read becomes a "not readable" line |
| `GET /installation/repositories` | leaked `ghs_` token | plan | validity and reach of an installation token |
| `GET /user` | the new token | apply | it must belong to the same login |
| `POST /credentials/revoke` | nothing | apply | revoke the leaked token |

The credential revocation API must be called without authentication (GitHub
answers an authenticated request with 403). It accepts classic (`ghp_`) and
fine-grained (`github_pat_`) personal access tokens, OAuth app tokens
(`gho_`), GitHub App user tokens (`ghu_`) and refresh tokens (`ghr_`), up to
1000 per request, and allows 60 requests per hour per IP address. GitHub
cannot reactivate a revoked token, so rollback cannot restore it.

GitHub App installation tokens (`ghs_`) are not accepted by that API. rotate
identifies and checks them but does not revoke or replace them: they expire
within an hour, and the app can revoke one early with
`DELETE /installation/token`.

GitHub has no API to create personal access tokens, so apply runs in manual
replacement mode: it names the page to create the new token on and, for a
classic token, the scopes to give it. Fine-grained permissions cannot be
read through the API; copy them from the leaked token's settings page.
`providers.github.api_url` points rotate at GitHub Enterprise Server.

## npm tokens (provider `npm`)

The leaked token signs only `GET /-/whoami`, which is read-only. Everything
else uses your operator token from `ROTATE_NPM_TOKEN`, then `NPM_TOKEN`. In
CI, `NPM_TOKEN` is often the leaked token itself, so set `ROTATE_NPM_TOKEN`.
rotate refuses to use the leaked token as the operator token.

Operator token requirement. The npm operator token must be an
`npm login` session token for the same account as the leaked token: npm's
token list accepts no other kind, granular access tokens included. A granular token
without 2FA bypass may delete tokens but cannot list them, and rotate needs
the list to find the token id; one with 2FA bypass gets a 403 on both. npm
revoked the classic automation tokens on 2025-12-09. The npm sources are in
[plans/SHA-292.md](plans/SHA-292.md).

| Call | Signed with | Used by | Why |
| --- | --- | --- | --- |
| `GET /-/whoami` | leaked token | plan | validity (200 valid, 401 invalid) and the npm user |
| `GET /-/npm/v1/tokens` | operator token | plan, apply | find the leaked token's entry: type, access, permissions, scopes, IP ranges, expiry, and its token id |
| `GET /-/whoami` | the new token | apply | it must belong to the same user |
| `DELETE /-/npm/v1/tokens/token/{id}` | operator token | apply | delete the leaked token |
| `GET /-/whoami` | leaked token | apply | only when the token list has no entry: a 401 means it is already deleted |

A session token lasts two hours and only `npm login` makes one, so npm
revoke cannot run unattended from CI on a stored token: run `npm login`
shortly before an unattended run and pass the new token as
`ROTATE_NPM_TOKEN`. Without a usable operator token the plan still shows
the user and says "token not visible to operator account", and the revoke
row gets a blocker: `no npm operator token` when none is set, or "npm
refused the operator token on the token list" when npm answers 401 or 403
(the scope line then says a session token is needed). Apply would update
the consumers and verify, then stop at revoke with the leaked token still
valid.

rotate deletes the token by the id npm lists for it, so the token value
never appears in a URL. It finds the entry by its redacted form (first 8
and last 4 characters) or, for older tokens, by the sha512 key. If two
entries fit the redacted form, rotate does not guess and asks you to delete
the token by hand.

npm may ask for a one-time password to delete a token. rotate does not send
one: the revoke fails and names the page to delete the token on
(`https://www.npmjs.com/settings/<user>/tokens`). Revoke is the last step,
so the consumers already hold the new token. A deleted token cannot be
restored, so rollback cannot bring it back.

npm creates tokens only with the account password and a one-time password,
so apply runs in manual replacement mode: it names the granular token page
and the permissions, scopes and IP ranges to copy. Read-write granular
tokens last at most 90 days. `providers.npm.registry` points rotate at
another registry.

## OpenAI API keys (provider `openai`)

The OpenAI provider uses an organization Admin API key as its operator
credential, read from `OPENAI_ADMIN_KEY` (or the variable named by
`providers.openai.admin_key_env`) when a call needs it. Create one at
platform.openai.com/settings/organization/admin-keys; it needs read and
write access to projects (projects, project API keys and project service
accounts). rotate refuses an admin key that is the key being rotated.

| Call | Signed with | Used by | Why |
| --- | --- | --- | --- |
| `GET /v1/models` | leaked key | plan, revoke | validity (200 and 429 valid, 401 invalid); without an admin key, the `openai-organization` header; at revoke, whether an unlisted key is already gone |
| `GET /v1/organization/projects` | admin key | plan, apply | find the key's project |
| `GET /v1/organization/projects/{id}/api_keys` | admin key | plan, apply | find the key by its redacted value, its owner and last use; verify the replacement is in the same project |
| `POST /v1/organization/projects/{id}/service_accounts` | admin key | apply | create the replacement: a service account named `rotate-<fingerprint hex>` and its key |
| `GET /v1/models` | new key | apply | the replacement works |
| `DELETE /v1/organization/projects/{id}/api_keys/{key_id}` | admin key | apply | revoke a user-owned key |
| `DELETE /v1/organization/projects/{id}/service_accounts/{id}` | admin key | apply, rollback | revoke a service-account key that is its account's only key; delete the replacement's service account |

OpenAI's key delete endpoint refuses service-account keys, so rotate removes
one by deleting its service account, and only when the listing shows the
account holds no other key. Otherwise the plan's revoke row says to delete
the key at platform.openai.com/api-keys and apply stops at the revoke step
with the consumers already updated. A key that is in no project the admin
key can list (a legacy user key) gets no scope and is not applied.

The Admin API does not expose a key's permissions, so the replacement
service account has the member role and all permissions; restrict it on
the dashboard if the leaked key was restricted. OpenAI cannot bring a
deleted key back, so rollback cannot restore the old key.

Without an admin key the provider runs in manual mode: apply asks for the
new key, accepts it once it works and reports the same `openai-organization`
header as the leaked key, and cannot revoke. Admin keys (`sk-admin-`) are
identified but not checked or rotated. `providers.openai.api_url` changes
the API base URL.
