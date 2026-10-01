# Security policy

rotate handles live credentials, so we treat security reports as the
highest priority.

## Supported versions

No version has been released yet. Until 1.0, only the latest release (and
`main`) receives fixes.

## How to report a vulnerability

Report it privately through GitHub: open the repository's **Security** tab
and choose **Report a vulnerability**
(<https://github.com/smhasan94/rotate/security/advisories/new>). Only the
maintainers can see the report.

Do not open a public issue, pull request or discussion for a vulnerability.

Please include:

- what an attacker could do, and under which conditions;
- the rotate version or commit, and the platform;
- steps to reproduce, with a minimal report file or config if needed.

**Never send a real secret.** Use a revoked credential or a placeholder such
as `<token>`, and give its fingerprint (`sha256:...`) if you need to point to
one. If you think a live secret reached a report by mistake, revoke it
first, then tell us.

## What to expect

- Acknowledgement within 3 working days.
- An assessment and a planned fix date within 10 working days.
- A GitHub security advisory and a credit (if you want one) when the fix is
  released.

## Scope

In scope, among others:

- a secret value appearing anywhere in plain text: stdout, stderr, tracing
  output, the audit log, the state file, error or panic messages;
- `rotate plan` making a state-changing API call;
- a revoke that runs after an earlier step failed, or while a consumer
  still holds the old secret without `--force`;
- a report or config file that makes rotate act on a key it did not list in
  the plan;
- weaknesses in the release workflow or published binaries.

Out of scope: vulnerabilities in the providers' own services (report those to
AWS, GitHub, npm or OpenAI), and findings that need an already compromised
operator machine.

## Our promise about secret values

rotate never logs, prints or stores a secret value. Values are held in
zeroized memory and wiped on drop. The audit log and state file hold
fingerprints only, so reading them reveals which keys exist, not the keys
themselves. Any way around this is a vulnerability; please report it as
above.
