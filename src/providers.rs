//! The provider registry the CLI runs with.
//!
//! No real provider is built in yet (SHA-251, SHA-260 to SHA-262). The
//! `test-providers` feature registers `MockProvider`s under the four real
//! names so integration tests can drive the CLI end to end. Release builds
//! never enable it.

use rotate::provider::ProviderRegistry;

/// Every provider this build knows.
pub fn registry() -> ProviderRegistry {
    #[allow(unused_mut)]
    let mut registry = ProviderRegistry::new();
    #[cfg(feature = "test-providers")]
    for (name, prefix) in [
        ("aws", "mock_aws_"),
        ("github", "ghp_"),
        ("npm", "npm_"),
        ("openai", "sk-"),
    ] {
        registry.register(std::sync::Arc::new(
            rotate::provider::mock::MockProvider::new(name).identify_prefix(prefix),
        ));
    }
    registry
}
