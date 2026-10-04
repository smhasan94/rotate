//! Where a provider gets a one-time password when the API asks for one
//! (SHA-288): npm answers a token delete on an account with 2FA on writes
//! with a challenge, and the code is valid about 30 seconds, so it is
//! obtained at the moment of the retry, never up front.
//!
//! This module has no terminal code. [`EnvOtp`] reads a variable once,
//! [`Chain`] asks sources in order, and the hidden terminal prompt lives
//! next to the other prompts (`apply::PromptOtp`).
//!
//! A six-digit code is shorter than [`crate::redact::MIN_LEN`], so the
//! redactor cannot find it in text. Callers keep it in a [`SecretValue`],
//! never format it, send it in a header marked sensitive, and drop it right
//! after the request.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;

use crate::secret::SecretValue;

/// Longest code accepted, in bytes. npm's are six digits.
pub const OTP_MAX: usize = 64;

/// Why no one-time password was returned. Never holds a value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OtpError {
    /// Nothing to ask: the variable is unset or already used, or there is
    /// no terminal.
    #[error("no one-time password was available")]
    NoSource,
    /// A source failed: the terminal could not be read, or the value is not
    /// usable. The text holds no value.
    #[error("{0}")]
    Failed(String),
}

/// A source of one-time passwords.
#[async_trait]
pub trait OtpSource: Send + Sync {
    /// One code, asked for with `question` when the source asks a person.
    /// `question` holds no value.
    async fn one_time_password(&self, question: &str) -> Result<SecretValue, OtpError>;
}

/// A code from an environment variable, read on the first challenge (never
/// at construction) and used for at most one request: a later call is
/// [`OtpError::NoSource`]. The variable itself is left alone; removing it
/// is unsound while other threads may read the environment.
pub struct EnvOtp {
    var: String,
    used: AtomicBool,
}

impl EnvOtp {
    /// A source reading `var`.
    pub fn new(var: impl Into<String>) -> Self {
        Self {
            var: var.into(),
            used: AtomicBool::new(false),
        }
    }
}

impl fmt::Debug for EnvOtp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvOtp")
            .field("var", &self.var)
            .field("used", &self.used.load(Ordering::SeqCst))
            .finish()
    }
}

#[async_trait]
impl OtpSource for EnvOtp {
    async fn one_time_password(&self, _question: &str) -> Result<SecretValue, OtpError> {
        if self.used.load(Ordering::SeqCst) {
            return Err(OtpError::NoSource);
        }
        let Some(raw) = std::env::var_os(&self.var) else {
            return Err(OtpError::NoSource);
        };
        let value = SecretValue::new(raw.into_encoded_bytes());
        let code = value.expose_secret(|bytes| SecretValue::new(bytes.trim_ascii().to_vec()));
        drop(value);
        if code.is_empty() {
            return Err(OtpError::NoSource);
        }
        self.used.store(true, Ordering::SeqCst);
        check(
            code,
            &format!("{} is not a usable one-time password", self.var),
        )
    }
}

/// `code` when it can go in a header and is not too long; `why` otherwise.
pub fn check(code: SecretValue, why: &str) -> Result<SecretValue, OtpError> {
    let usable = code.expose_secret(|bytes| {
        !bytes.is_empty() && bytes.len() <= OTP_MAX && bytes.iter().all(u8::is_ascii_graphic)
    });
    if usable {
        Ok(code)
    } else {
        Err(OtpError::Failed(why.to_owned()))
    }
}

/// Asks each source in order until one returns something other than
/// [`OtpError::NoSource`].
pub struct Chain(pub Vec<Arc<dyn OtpSource>>);

impl fmt::Debug for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Chain({} sources)", self.0.len())
    }
}

#[async_trait]
impl OtpSource for Chain {
    async fn one_time_password(&self, question: &str) -> Result<SecretValue, OtpError> {
        for source in &self.0 {
            match source.one_time_password(question).await {
                Err(OtpError::NoSource) => continue,
                other => return other,
            }
        }
        Err(OtpError::NoSource)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(&'static str);

    #[async_trait]
    impl OtpSource for Fixed {
        async fn one_time_password(&self, _: &str) -> Result<SecretValue, OtpError> {
            Ok(SecretValue::from(self.0))
        }
    }

    // SHA-288 T7 (unit): single use, and the chain falls through.
    #[tokio::test]
    async fn env_otp_reads_once_and_chain_falls_through() {
        let var = "ROTATE_TEST_OTP_UNIT_ONCE";
        std::env::set_var(var, " 1234567\n");
        let env = EnvOtp::new(var);
        let code = env.one_time_password("q").await.unwrap();
        assert!(code.expose_secret(|b| b == b"1234567"));
        assert_eq!(
            env.one_time_password("q").await.unwrap_err(),
            OtpError::NoSource
        );
        assert!(format!("{env:?}").contains("used: true"));
        assert!(!format!("{env:?}").contains("1234567"));
        // The variable is consumed, not cleared.
        assert!(std::env::var(var).is_ok());

        let chain = Chain(vec![Arc::new(env), Arc::new(Fixed("7654321"))]);
        let code = chain.one_time_password("q").await.unwrap();
        assert!(code.expose_secret(|b| b == b"7654321"));
        std::env::remove_var(var);

        let unset = EnvOtp::new("ROTATE_TEST_OTP_UNIT_UNSET");
        assert_eq!(
            unset.one_time_password("q").await.unwrap_err(),
            OtpError::NoSource
        );
        assert_eq!(
            Chain(vec![]).one_time_password("q").await.unwrap_err(),
            OtpError::NoSource
        );
    }

    #[tokio::test]
    async fn unusable_codes_are_refused_without_the_value() {
        let var = "ROTATE_TEST_OTP_UNIT_BAD";
        std::env::set_var(var, "12 34\u{7f}5");
        let err = EnvOtp::new(var).one_time_password("q").await.unwrap_err();
        std::env::remove_var(var);
        let OtpError::Failed(text) = err else {
            panic!("{err:?}");
        };
        assert!(text.contains(var), "{text}");
        assert!(!text.contains("12 34"), "{text}");
        assert!(check(SecretValue::from("1".repeat(OTP_MAX + 1)), "too long").is_err());
        assert!(check(SecretValue::from("123456"), "x").is_ok());
    }
}
