//! Fixtures that wire the mocks into the suite: the reference wiring a real
//! plugin's test copies, and what this crate's own suite tests use.

use std::sync::Arc;

use super::{ConsumerFixture, ProviderFixture};
use crate::consumer::mock::MockConsumer;
use crate::consumer::{ConsumerMatch, SecretRef};
use crate::provider::mock::MockProvider;
use crate::provider::Credential;
use crate::secret::SecretValue;

/// `mock` with a live credential, an unknown one it treats as revoked, and
/// its own call log as the probe.
pub fn provider_fixture(mock: MockProvider) -> ProviderFixture {
    let live = Credential::Token(SecretValue::from("mock_conformance_live_value"));
    let unknown = Credential::Token(SecretValue::from("mock_conformance_unknown_value"));
    let mock = mock.revoked(unknown.fingerprint());
    ProviderFixture {
        identity: mock.identity(),
        probe: Box::new(mock.call_log()),
        provider: Arc::new(mock),
        live,
        unknown,
    }
}

/// `mock` storing an old credential in two places, one matched by value
/// and one by name, with its own call log as the probe.
pub fn consumer_fixture(mock: MockConsumer) -> ConsumerFixture {
    let old = Credential::Token(SecretValue::from("mock_conformance_old_value"));
    let new = Credential::Token(SecretValue::from("mock_conformance_new_value"));
    let mock = mock
        .matching(
            old.fingerprint(),
            ConsumerMatch::by_value("mock:conformance/by-value"),
        )
        .matching(
            old.fingerprint(),
            ConsumerMatch::by_name("mock:conformance:BY_NAME"),
        );
    ConsumerFixture {
        secret: SecretRef::new("mock", &old).with_names(["BY_NAME"]),
        probe: Box::new(mock.call_log()),
        consumer: Arc::new(mock),
        old,
        new,
    }
}
