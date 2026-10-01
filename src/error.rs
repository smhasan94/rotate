//! The error type that reaches `main` (SHA-246, NFR2).
//!
//! [`Error`] wraps any error and redacts its message and source chain every
//! time it is formatted, with `Display` or `Debug`. Formatting happens late,
//! so a value registered after the error was built is still caught.

use std::fmt;

use zeroize::Zeroizing;

use crate::redact::redact;

type Source = Box<dyn std::error::Error + Send + Sync + 'static>;

/// An error on its way to `main`, redacted whenever it is formatted.
///
/// It does not implement [`std::error::Error`] itself, so that any error
/// converts into it with `?` (the same trade-off `anyhow::Error` makes).
pub struct Error {
    inner: Source,
}

impl Error {
    /// Wraps an error.
    pub fn new(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self {
            inner: Box::new(err),
        }
    }

    /// An error with only a message.
    pub fn msg(message: impl fmt::Display) -> Self {
        Self {
            inner: message.to_string().into(),
        }
    }

    /// The wrapped error.
    pub fn inner(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        &*self.inner
    }

    /// The message and every source, joined by `: `, redacted.
    fn redacted(&self) -> Zeroizing<String> {
        let mut text = Zeroizing::new(self.inner.to_string());
        let mut source = self.inner.source();
        while let Some(err) = source {
            text.push_str(": ");
            text.push_str(&Zeroizing::new(err.to_string()));
            source = err.source();
        }
        Zeroizing::new(redact(&text).into_owned())
    }
}

impl<E: std::error::Error + Send + Sync + 'static> From<E> for Error {
    fn from(err: E) -> Self {
        Self::new(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.redacted())
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Error").field(&&*self.redacted()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::ProviderError;
    use crate::secret::SecretValue;

    #[derive(Debug, thiserror::Error)]
    #[error("rotation failed")]
    struct Outer(#[source] ProviderError);

    // T2 unit half (AC2)
    #[test]
    fn display_and_debug_redact_chain() {
        let canary = ["error-rs-canary-", "4b81d0c2"].concat();
        let secret = SecretValue::from(canary.as_str());
        let err: Error = Outer(ProviderError::Permanent(format!("upstream said {canary}"))).into();
        let marker = format!("[REDACTED {}]", secret.fingerprint());

        let display = err.to_string();
        assert!(display.starts_with("rotation failed: "), "{display}");
        assert!(display.contains(&marker), "{display}");
        assert!(!display.contains(&canary));

        let debug = format!("{err:?}");
        assert!(debug.starts_with("Error("), "{debug}");
        assert!(debug.contains(&marker), "{debug}");
        assert!(!debug.contains(&canary));
    }

    #[test]
    fn msg_keeps_plain_text() {
        let err = Error::msg("nothing secret here");
        assert_eq!(err.to_string(), "nothing secret here");
        assert_eq!(err.inner().to_string(), "nothing secret here");
    }

    #[test]
    fn redacts_values_registered_after_creation() {
        let canary = ["error-rs-late-", "77e1a9f3"].concat();
        let err = Error::msg(format!("saw {canary}"));
        let secret = SecretValue::from(canary.as_str());
        assert!(!err.to_string().contains(&canary));
        drop(secret);
    }
}
