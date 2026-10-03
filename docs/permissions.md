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
| `iam:GetAccessKeyLastUsed` | plan, apply, rollback | owner of the leaked key (or of the replacement, on rollback) and when each key was last used |
| `iam:GetUser` | plan | the owner's ARN, which the replacement must match |
| `iam:ListAttachedUserPolicies`, `iam:ListUserPolicies`, `iam:ListGroupsForUser` | plan | scope lines; a denied read becomes a "not visible" line |
| `iam:ListAccessKeys` | plan, apply | key slots: IAM allows two keys per user |
| `iam:CreateAccessKey` | apply | the replacement key |
| `iam:UpdateAccessKey` | apply, rollback | deactivate the leaked key; on rollback reactivate it and deactivate the replacement |

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
