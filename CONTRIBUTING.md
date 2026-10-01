# Contributing

Thanks for helping. rotate handles live credentials, so the safety rules in
[README.md](README.md#safety-guarantees) apply to every change. To report a
vulnerability, follow [SECURITY.md](SECURITY.md) instead of opening an issue.

## Setup

Rust stable, edition 2021. `rust-toolchain.toml` pins the channel. Install
the extra tools once:

```sh
rustup component add rustfmt clippy
cargo install cargo-deny --locked
```

## Checks

Run all four before opening a pull request. CI runs the same commands on
Linux and macOS, and all of them must pass before merge.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo deny check
```

CI also runs `ci/check-docs.sh`, which checks that the block above matches
`CLAUDE.md` and that the README and SECURITY.md keep their key sections.

## Work items

Every change starts from a ticket in the Linear project "rotate". Bigger
tickets get a short implementation plan in `docs/plans/SHA-<n>.md` before
the code.

## Branches

Trunk-based on `main`. Name a branch after its ticket: the lowercase Linear
identifier, a hyphen, and a short slug of the title, for example
`sha-42-zeroized-secret-type`.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`,
`fix:`, `docs:`, `test:`, `ci:`, `refactor:`, `chore:`, with an optional
scope, such as `feat(config): ...`. Put the ticket id in the subject or body.

## Pull requests

All code changes go through a pull request; nothing else is pushed to
`main`. The one exception is `docs/plans/` and `docs/backlog.md`, which may
be committed directly.

The pull request template asks for the Linear link, any changes to the
ticket, and a table mapping each T-case to its test. A ticket is done when
every T-case passes in CI, the four checks pass, docs are updated, and the
pull request is reviewed and merged.

## Dependencies

Keep the dependency set small. `deny.toml` allows only licenses compatible
with Apache-2.0 and rejects known advisories. If a new crate needs a license
that is not on the allowlist, say why in the pull request and add a note
here.

HTTP, TLS and the AWS SDK (decided in SHA-273, see
`docs/plans/SHA-273.md`):

- `reqwest` uses `default-features = false` with `rustls-tls-native-roots`.
  Certificates come from the OS trust store, so corporate TLS-inspecting
  proxies and private CAs work. A minimal container image needs CA
  certificates installed. The bundled-roots feature (`rustls-tls`) brings
  `webpki-roots`, whose CDLA-Permissive-2.0 license is not on the allowlist.
- The AWS SDK crates (`aws-config`, `aws-sdk-*`) use
  `default-features = false` with `default-https-client` and `rt-tokio`
  (plus `behavior-version-latest` on `aws-config`). Their default features
  pull a legacy `hyper` 0.14 / `rustls` 0.21 stack with open advisories;
  `deny.toml` bans it, so `cargo deny check` fails if it comes back.

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
- Test it against wiremock (see "Writing tests") and pass the shared
  conformance suite (SHA-249) from an integration test:

  ```rust
  use rotate::conformance::{provider_suite, MutationProbe, ProviderFixture};

  #[tokio::test]
  async fn conformance() {
      provider_suite(|| async {
          let server = common::CallRecorder::start().await;
          // Mount answers: `live` is valid and owned by `identity`, a
          // second revoke of it still succeeds, `unknown` gets the
          // provider's real 401 or 404.
          ProviderFixture {
              provider: Arc::new(MyProvider::new(server.uri())),
              live, identity, unknown,
              probe: Box::new(RecorderProbe(server)),
          }
      })
      .await
      .assert_ok();
  }
  ```

  The factory runs once per check, so every check gets a fresh plugin and
  server. `RecorderProbe` is your few-line `MutationProbe` impl returning a
  method-and-path label for each `RecordedCall` with `mutating` set. The
  suite returns a `SuiteReport` naming each failed check; `assert_ok`
  panics with it. `rotate::conformance::mock::provider_fixture` shows the
  same wiring for `MockProvider`.

`provider::mock::MockProvider` is the reference double: it records every
call into a `CallLog` with the mutating flag, and tests inject failures with
`fail_next` or `fail_always`.

## Adding a consumer

A consumer is one implementation of `rotate::consumer::Consumer` (SHA-222):
a place where a credential is stored for use.

- `find` is read-only. Match by value fingerprint where the service lets you
  read the value back (`MatchMethod::ByValue`). Otherwise match by the names
  in `SecretRef::names` (`ByName`, as for GitHub Actions secrets). Set
  `holds` to the part of the credential the match stores: the secret, the
  AWS key id, or both.
- When a match cannot be updated automatically, return it with
  `not_updatable(reason)` rather than leaving it out. The plan shows the
  reason and apply refuses to revoke without `--force`. `update` on such a
  match must return `ConsumerError::NotUpdatable`.
- `update` writes the part of the new credential that the match holds, and
  `restore` writes the old one back. These are the only mutating methods,
  listed in `consumer::MUTATING`. Use `ConsumerMatch::value_fingerprint` to
  see which part a match holds.
- Never put a value in `consumer_ref`, a not-updatable reason or an error
  message; those strings reach the plan output and the audit log.
- Register it in the `ConsumerRegistry` the CLI builds, and pass
  `rotate::conformance::consumer_suite` from an integration test against
  wiremock. Its `ConsumerFixture` holds the consumer, the `old` credential
  the server stores, the `new` one the suite writes, the `SecretRef` for
  `old` (with the name hints a by-name store needs) and a `MutationProbe`.
  `rotate::conformance::mock::consumer_fixture` is the reference wiring.

`consumer::mock::MockConsumer` is the reference double. It shares
`CallLog` with `MockProvider`, keeps the fingerprint each consumer holds
(`current`), and adds `fail_for(method, consumer_ref, error)` for failing
one consumer out of several.
