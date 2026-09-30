# Contributing

This file is a stub. SHA-213 fills in the rest (branch naming, commits,
pull requests). The testing section below is owned by SHA-216.

## Writing tests

Three kinds of test, and where each lives:

- **Unit tests** sit in `src/` next to the code in a `#[cfg(test)] mod tests`.
- **Integration tests** sit in `tests/`. They never touch the network except a
  wiremock server started in the test. Include the shared helpers with
  `mod common;` and start a server with `common::CallRecorder::start().await`.
  Use `rec.calls().await` to inspect what was sent and
  `rec.assert_no_mutations().await` to prove a dry run made no
  state-changing call. Mark read-only POST routes (AWS query calls) with
  `rec.mark_read_only(|req| ...)`. Use `common::TestDirs::new()` for a temp
  working directory with `.rotate/`.
- **Live tests** call real provider APIs. Name them `live_*`, mark them
  `#[ignore]`, and start the body with `live_guard!();`. They run only with:

  ```sh
  ROTATE_LIVE_TESTS=1 cargo test --all-features -- --ignored live_
  ```

  Default CI never sets that variable and asserts the live tests show as
  ignored.

Never print a request body or a secret in a test: recorded calls show
`body_len` in `Debug`, and assertion messages name calls by method and path.
If a test must inspect a body, call `.body()` and assert on it.

## Handling secret values

Every credential the tool touches is a `rotate::secret::SecretValue`
(SHA-217). Never hold a secret in a `String`, `Vec<u8>` or `&str` outside of
the closure that uses it.

- Build one with `SecretValue::from(...)` or `SecretValue::from_reader(...)`,
  or let serde build it: the type implements `Deserialize`, so report and
  stdin structs can declare `raw: SecretValue` directly.
- Read the bytes only with `expose_secret(|bytes| ...)` or
  `expose_secret_str(|s| ...)`, at the call that sends them (a request
  header, a request body). Keep the closure small and return a non-secret
  result from it.
- Print or log the `fingerprint()` instead. `Debug` and `Display` on
  `SecretValue` already do this, so `{:?}` and `{}` are safe; the plaintext
  has no formatting path at all.
- Never derive `Serialize` on a struct that holds a `SecretValue`; it will
  not compile, and that is the point. Serialize the `Fingerprint` instead.
- For AWS keys use `SecretPair { key_id, secret }`; only the secret half is
  protected and the fingerprint is computed over it.
- Every ticket that touches secret values adds a test proving the value never
  reaches stdout, stderr, tracing output or the audit log. `tests/secret_leak.rs`
  shows the pattern: format into an in-memory writer, capture tracing with a
  subscriber writing to a shared buffer, and assert the plaintext is absent.

## Adding a provider

A provider is one implementation of `rotate::provider::Provider` (SHA-221).

- Implement every method. `identify` is pure and looks at the finding's
  detector hint and the shape of the value. `check_valid`, `describe_scope`
  and `verify` must be read-only on the real service; `create_replacement`,
  `revoke` and `restore` are the only methods allowed to change state, and
  they are the ones listed in `provider::MUTATING`. Keep that list in step
  with the trait.
- Take a `Credential`, not a bare `SecretValue`. AWS needs the key id to
  sign; everything else uses `Credential::Token`. Return
  `ProviderError::Unsupported` for the wrong kind rather than panicking.
- Never put a value in an error message, a `Scope` line or a
  `replacement_ref`; those strings reach the plan output and the audit log.
- Register it in the `ProviderRegistry` the CLI builds, and give it a short
  stable `name()` that the config and audit log use.
- Test it against wiremock (see "Writing tests") and run the shared
  conformance suite once SHA-249 lands. Until then, mirror the assertions in
  `tests/provider_leak.rs` with a canary value.

`provider::mock::MockProvider` is the reference double: it records every
call into a `CallLog` with the mutating flag, and tests inject failures with
`fail_next` or `fail_always`.
