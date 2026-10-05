# Security model

What rotate guarantees about the secrets it handles, how it keeps those
guarantees, and what it does not protect. The full requirements and threat
model are in [requirements.md](requirements.md); how to report a
vulnerability is in [SECURITY.md](../SECURITY.md).

## The four guarantees

These are the safety requirements from the project brief, word for word.
A change that breaks one is not merged, and each has tests that prove it.

1. Secret values are never printed, logged or written to disk in plain text and are held in zeroized memory buffers.
2. Dry run makes zero state-changing API calls.
3. Any failure during apply stops before the revoke step and leaves the system usable.
4. The tool refuses to revoke a secret whose consumers could not all be updated unless `--force` is given.

How each one holds:

1. **No plain text.** A secret lives only in one type (`SecretValue`) whose
   memory is wiped when it is dropped, which cannot be serialized, and
   whose debug output is its fingerprint. Every byte rotate writes to
   stdout, stderr, the tracing log, the audit log, the state file, an
   error or a panic message passes through a redaction layer that replaces
   every live secret value, and anything shaped like a provider token, with
   a fingerprint marker. A leakage test (`tests/leakage.rs`) runs every
   command with canary secrets and searches every output stream and file
   for them. Secrets are never accepted as command-line arguments: use a
   report, `--stdin`, a hidden prompt, `--replacement-from-env` or
   `--replacement-file`.
2. **Dry run.** `rotate plan` only makes read-only calls: validity checks,
   scope lookups, consumer searches and, with `--check-permissions`, policy
   simulation. Its one write is local (the `planned` record in the state
   file). Tests run it against mocks that record every call and fail on
   any state-changing one.
3. **Revoke last.** apply runs create, update, verify, revoke, in that
   order, and saves state after each step. Any failure before revoke stops
   that rotation with the old secret still working; re-running resumes
   without repeating a step, and `rotate rollback` undoes what was done.
4. **No revoke past a consumer.** A consumer that could not be updated
   holds the revoke and apply exits 1. `--force` revokes anyway, but never
   past a failed create or verify, and it is recorded in the state file and
   as a `force` audit entry, with the actor, before the revoke.

Two more properties follow from the design:

- rotate never uses the leaked secret as its own credential. The only
  calls signed with it are read-only validity checks. Everything else uses
  your operator credentials from the environment.
- apply verifies that the replacement works and belongs to the same owner
  before anything is revoked, so a wrong or swapped replacement fails
  closed.

## Fingerprints

rotate names a secret by its fingerprint everywhere: in output, logs, the
audit log and the state file. A fingerprint is `sha256:` followed by the
first 16 hex characters (64 bits) of the SHA-256 digest of the secret
value, for example `sha256:8088a3c392bc0b3e`. For an AWS key pair it is
computed over the secret access key. The same secret always has the same
fingerprint, so you can match it across runs, machines and tools, and the
value cannot be recovered from it: the four providers' secrets are long
random strings, so an unsalted digest cannot be brute-forced.

To find the fingerprint of a secret you hold, run `rotate plan --stdin` and
paste it.

## The audit log

Default `.rotate/audit.jsonl` (`audit_log` in [config.md](config.md)).
One JSON object per line, appended for every step of every rotation and
rollback, and never rewritten. Each line has:

| Field | Content |
| --- | --- |
| `version` | Schema version, `1`. |
| `ts` | Time, UTC, RFC 3339. |
| `actor` | `ROTATE_ACTOR` if set, else `user@hostname`. Informational, not authenticated. |
| `rotation_id` | The rotation (`rot-...`). |
| `provider` | `aws`, `github`, `npm` or `openai`. |
| `fingerprint` | The old secret's fingerprint. |
| `replacement_fingerprint` | The replacement's fingerprint, once there is one. |
| `consumer` | The consumer reference on `update` entries, such as `github-actions:acme/api:AWS_SECRET_ACCESS_KEY`. |
| `replacement_mode` | `automatic` or `manual`, on `create` entries. |
| `action` | `restore_old`, `restore_consumer` or `revoke_replacement`, on `rollback` entries. |
| `step` | `identify`, `check`, `plan`, `create`, `update`, `verify`, `revoke`, `rollback` or `force`. |
| `outcome` | `ok`, `failed` or `skipped`. |
| `error` | Why it failed, redacted. |

It never holds a secret value. It does hold public identifiers: rotation
ids, fingerprints, consumer references, and in error text identifiers such
as AWS access key ids or IAM user names. Each line is written in one
append and synced, so a killed process leaves whole lines.

## Files on disk

rotate keeps two files, both under `./.rotate/` by default:

- the audit log (above);
- the state file (`.rotate/state.json`): each rotation's id, provider,
  fingerprints, the replacement's provider reference (an AWS access key id,
  a token id, or `manual`), the step reached, each consumer's status, the
  pending revoke time, and whether `--force` was used. No secret values.

Both are created with mode 0600 (owner only) inside a directory created
with mode 0700. An existing file whose mode lets other users read it is
refused with an error that says to check who could have read it and run
`chmod 600`. The state file is replaced atomically, and commands that
change it hold an exclusive lock on `state.json.lock` next to it, so two
rotate processes cannot interleave; the second exits 2. `--replacement-file` must also be mode 600 or rotate refuses it.

## Threat model in brief

From [requirements.md](requirements.md#10-threat-model).

What an attacker could gain from rotate itself:

- A malicious report could aim create and revoke at keys the attacker
  chose, revoking live keys.
- A compromised binary or dependency would see every secret rotate handles
  and your operator credentials.
- A compromised consumer updater could write attacker-chosen values into CI
  secrets or Secrets Manager.
- The audit log and state file reveal which keys exist and their rotation
  history.
- A misused `--force` could revoke a key whose consumers were not updated.

How the design limits that:

- Dry run by default and typed confirmation for apply. Scripts must name
  each rotation id with `--confirm`, so they cannot apply a plan they did
  not print. Nothing outside the printed plan runs.
- Secret values exist only in wiped memory; the files hold fingerprints.
- rotate uses your existing operator credentials and needs none of its
  own; [permissions.md](permissions.md) lists the minimum each provider
  needs so you can scope them.
- Revoke is last and skipped on any earlier failure; `--force` is audited
  with the actor.
- Verification before revoke: the replacement must prove it belongs to the
  same identity.
- Supply chain: `cargo deny` checks advisories and licenses on every pull
  request, the dependency set is small, and tests make no network call
  except to local mock servers.

## Limits

What rotate does not protect against:

- **Memory dumps.** Secrets are wiped when rotate is done with them, but
  while it runs they are in process memory. rotate does not lock pages in
  memory or disable core dumps, so swap, a core dump, a debugger or anyone
  who can read the process's memory as your user or as root can see them.
  Copies made by libraries (the HTTP client, the TLS stack, the AWS SDK)
  are not wiped.
- **Your operator credentials and environment.** rotate reads AWS, GitHub,
  npm and OpenAI operator credentials from the environment and the AWS
  config files. Anyone who can read your environment, shell history or
  `~/.aws` has them; rotate cannot protect them. `--replacement-from-env`
  values are visible to other processes of your user while set.
- **Input files.** The scanner report you give rotate contains the leaked
  secrets in plain text, and a `--replacement-file` holds the new one.
  rotate does not delete or wipe either; that is up to you.
- **What the leaked secret was used for.** rotate replaces and revokes the
  secret; it does not tell you what an attacker did with it before that.
  Check the provider's own logs (CloudTrail, GitHub audit log, npm and
  OpenAI usage). An overlap window keeps the leaked secret valid longer.
- **Consumers it does not know about.** rotate updates only the consumers
  listed in `rotate.yaml` and found by name or value. A copy anywhere else
  (a laptop, another CI system, a different repo) breaks when the old
  secret is revoked.
- **Tampering with the audit log.** The audit log is a plain file you own.
  It is not signed or hash-chained, and the actor is whatever
  `ROTATE_ACTOR` or the OS says. It records what happened; it does not
  prove it.
- **Redaction of unknown formats.** Redaction replaces the exact values
  rotate holds and every string shaped like a known provider token. A
  secret transformed in a way rotate does not know (re-encoded, split
  across writes by another tool) is not recognised. rotate's own output
  never does that, but a wrapper script that echoes the report might.
- **Short values.** The redactor ignores values shorter than 8 bytes, so it
  cannot catch a one-time password (npm's are six digits). rotate keeps
  such a code in zeroized memory, sends it only in a header marked
  sensitive, never writes it into any message, and drops it after the one
  request.
- **Fingerprints of weak secrets.** The fingerprint is an unsalted digest.
  It is safe for the four providers' random tokens; it would not be safe
  for a short or guessable secret.
- **Platforms.** File permission checks assume Linux or macOS. Windows is
  not supported.
