# Operator permissions

rotate never uses a leaked secret as its own credential (decision D3). It
acts with the operator's credentials, so scope those to what rotate needs.

## AWS IAM access keys (provider `aws`)

The leaked key signs one call only: `sts:GetCallerIdentity`, the validity
check in `rotate plan`. That call needs no permission.

Everything else uses the operator's AWS credentials from the default chain
(environment, shared profile, SSO or credential process), in the region from
`providers.aws.region`, else `AWS_REGION` / `AWS_DEFAULT_REGION`, else the
profile, else `us-east-1`. Without operator credentials `rotate plan` still
reports validity and shows the scope as unavailable.

| Action | Used by | Why |
| --- | --- | --- |
| `iam:GetAccessKeyLastUsed` | plan, apply, restore | owner of the leaked key and when each key was last used |
| `iam:GetUser` | plan | the owner's ARN, which the replacement must match |
| `iam:ListAttachedUserPolicies`, `iam:ListUserPolicies`, `iam:ListGroupsForUser` | plan | scope lines; a denied read becomes a "not visible" line |
| `iam:ListAccessKeys` | plan, apply | key slots: IAM allows two keys per user |
| `iam:CreateAccessKey` | apply | the replacement key |
| `iam:UpdateAccessKey` | apply, restore | deactivate the leaked key; reactivate it on rollback |

rotate never calls `iam:DeleteAccessKey`. When the user already has two
keys, the plan shows a warning and apply refuses to create a replacement:
delete the key that is not leaked yourself, then run apply again.

A policy that limits these to the users rotate may touch:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
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
    }
  ]
}
```

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
