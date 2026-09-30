//! Secret values held in memory that is wiped on drop (SHA-217).
//!
//! [`SecretValue`] is the only type in this crate allowed to hold the bytes
//! of a credential. It cannot be serialized, its `Debug` and `Display`
//! output is its [`Fingerprint`], and the bytes are reachable only through
//! [`SecretValue::expose_secret`]. [`SecretPair`] carries an AWS access key id
//! next to its secret half.
//!
//! What this module does not do: lock pages in memory, block core dumps, or
//! scrub copies that other code makes. Those are Later tickets and the
//! redaction layer (SHA-218) respectively.

use std::fmt::{self, Write as _};
use std::io::{self, Read};
use std::str::Utf8Error;

use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Bytes reserved before reading a secret from a reader, so that a typical
/// credential arrives without the buffer growing. Growth reallocates, and the
/// old allocation is freed without being wiped.
const READ_RESERVE: usize = 4096;

/// Prefix of every fingerprint; assumption A1 in `docs/requirements.md`.
const FINGERPRINT_PREFIX: &str = "sha256:";

/// Number of hex characters kept from the digest.
const FINGERPRINT_HEX_LEN: usize = 16;

/// A credential value in zeroized memory.
///
/// Construct it with [`SecretValue::new`], the `From` impls, or
/// [`SecretValue::from_reader`]. Read the bytes only through
/// [`expose_secret`](Self::expose_secret) at the call that needs them.
///
/// The type has no `Serialize` impl, so a struct that derives `Serialize` with
/// a `SecretValue` field does not compile. This is what keeps a secret out of
/// the audit log and the state file:
///
/// ```compile_fail
/// let secret = rotate::secret::SecretValue::from("hunter2");
/// let _ = serde_json::to_string(&secret);
/// ```
///
/// The fingerprint, by contrast, serializes freely:
///
/// ```
/// let secret = rotate::secret::SecretValue::from("hunter2");
/// let json = serde_json::to_string(&secret.fingerprint()).unwrap();
/// assert!(json.starts_with("\"sha256:"));
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    /// Wraps the given bytes. The caller's original buffer is moved, not
    /// copied, when it is already a `Vec<u8>` or `String`.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(Zeroizing::new(bytes.into()))
    }

    /// Reads the whole reader into a new secret.
    ///
    /// The buffer is pre-reserved with [`READ_RESERVE`] bytes. Input longer
    /// than that still works, but the reallocation leaves an unwiped copy of
    /// the first part behind.
    pub fn from_reader(mut reader: impl Read) -> io::Result<Self> {
        let mut buf = Zeroizing::new(Vec::with_capacity(READ_RESERVE));
        reader.read_to_end(&mut buf)?;
        Ok(Self(buf))
    }

    /// Runs `f` on the secret bytes and returns its result.
    ///
    /// Keep the closure small and never let the bytes escape it into a type
    /// that can be printed or serialized.
    pub fn expose_secret<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(&self.0)
    }

    /// Like [`expose_secret`](Self::expose_secret) but as `&str`, for
    /// providers that put the value in a header. Returns the UTF-8 error
    /// instead of calling `f` when the bytes are not valid UTF-8.
    pub fn expose_secret_str<R>(&self, f: impl FnOnce(&str) -> R) -> Result<R, Utf8Error> {
        std::str::from_utf8(&self.0).map(f)
    }

    /// Length of the secret in bytes. Not itself sensitive for the high
    /// entropy tokens rotate handles.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when the secret holds no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Stable one-way digest of the value (FR21), safe to print and store.
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.0)
    }
}

impl From<String> for SecretValue {
    fn from(value: String) -> Self {
        Self::new(value.into_bytes())
    }
}

impl From<Vec<u8>> for SecretValue {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecretValue {
    fn from(value: &str) -> Self {
        Self::new(value.as_bytes())
    }
}

impl From<&[u8]> for SecretValue {
    fn from(value: &[u8]) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretValue({})", self.fingerprint())
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Constant-time comparison through `subtle`. A length mismatch is reported
/// as unequal without comparing bytes; the length of a token is not what an
/// attacker is after.
impl PartialEq for SecretValue {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice().ct_eq(other.0.as_slice()).into()
    }
}

impl Eq for SecretValue {}

/// Accepts a string or a byte string. An owned string from the deserializer
/// is moved into the zeroized buffer; a borrowed one is copied, and the
/// deserializer's own input buffer is the caller's to wipe.
impl<'de> Deserialize<'de> for SecretValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SecretVisitor;

        impl Visitor<'_> for SecretVisitor {
            type Value = SecretValue;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string holding a secret value")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(SecretValue::from(v))
            }

            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(SecretValue::from(v))
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                Ok(SecretValue::from(v))
            }

            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                Ok(SecretValue::from(v))
            }
        }

        deserializer.deserialize_string(SecretVisitor)
    }
}

/// `sha256:` plus the first 16 hex characters of the SHA-256 of a secret.
///
/// Printable, serializable and usable as a map key. The same value always
/// gives the same fingerprint and the value cannot be recovered from it.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Fingerprint(String);

impl Fingerprint {
    /// Computes the fingerprint of raw bytes. Prefer
    /// [`SecretValue::fingerprint`]; this exists for the AWS pair and for
    /// tests.
    pub fn of(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        let mut text = String::with_capacity(FINGERPRINT_PREFIX.len() + FINGERPRINT_HEX_LEN);
        text.push_str(FINGERPRINT_PREFIX);
        for byte in &digest[..FINGERPRINT_HEX_LEN / 2] {
            // Writing to a String cannot fail.
            let _ = write!(text, "{byte:02x}");
        }
        Self(text)
    }

    /// The fingerprint as text, for example `sha256:ba7816bf8f01cfea`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Error for a string that is not a well-formed fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidFingerprint(String);

impl fmt::Display for InvalidFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid fingerprint {:?}: expected {FINGERPRINT_PREFIX} followed by {FINGERPRINT_HEX_LEN} lowercase hex characters",
            self.0
        )
    }
}

impl std::error::Error for InvalidFingerprint {}

impl TryFrom<String> for Fingerprint {
    type Error = InvalidFingerprint;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let hex = value.strip_prefix(FINGERPRINT_PREFIX).unwrap_or_default();
        let well_formed = hex.len() == FINGERPRINT_HEX_LEN
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if well_formed {
            Ok(Self(value))
        } else {
            Err(InvalidFingerprint(value))
        }
    }
}

impl std::str::FromStr for Fingerprint {
    type Err = InvalidFingerprint;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl From<Fingerprint> for String {
    fn from(value: Fingerprint) -> Self {
        value.0
    }
}

/// An AWS access key: a printable key id and a secret access key.
///
/// Only the secret half is a [`SecretValue`]. The fingerprint is computed
/// over the secret access key (assumption A1).
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct SecretPair {
    /// The access key id, for example `AKIAIOSFODNN7EXAMPLE`. Not a secret.
    pub key_id: String,
    /// The secret access key.
    pub secret: SecretValue,
}

impl SecretPair {
    /// Pairs a key id with its secret.
    pub fn new(key_id: impl Into<String>, secret: SecretValue) -> Self {
        Self {
            key_id: key_id.into(),
            secret,
        }
    }

    /// Fingerprint of the secret half.
    pub fn fingerprint(&self) -> Fingerprint {
        self.secret.fingerprint()
    }
}

impl fmt::Debug for SecretPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretPair")
            .field("key_id", &self.key_id)
            .field("secret", &self.secret)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAINTEXT: &str = "hunter2-abc";

    // T1 (AC1)
    #[test]
    fn debug_and_display_show_fingerprint_not_value() {
        let secret = SecretValue::from(PLAINTEXT);
        let expected = secret.fingerprint().to_string();
        for rendered in [
            format!("{secret:?}"),
            format!("{secret}"),
            format!("{secret:#?}"),
        ] {
            assert!(!rendered.contains(PLAINTEXT), "value leaked");
            assert!(rendered.contains("sha256:"), "no fingerprint in {rendered}");
            assert_eq!(rendered, format!("SecretValue({expected})"));
        }
    }

    // T2 (AC2): the wipe covers the whole allocation, observed on a live
    // value. `zeroize` writes zero to every byte up to `capacity()` and then
    // clears, so the spare capacity is initialized memory by the time it is
    // read here. Reading after drop would be undefined behaviour and is not
    // attempted; the drop path is covered by the trait bound test below.
    #[test]
    #[allow(unsafe_code)]
    fn zeroize_wipes_whole_capacity() {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(PLAINTEXT.as_bytes());
        let mut secret = SecretValue::from(bytes);
        let capacity = secret.0.capacity();
        assert!(capacity >= 64, "test needs spare capacity");

        secret.zeroize();

        assert!(secret.0.is_empty());
        assert_eq!(
            secret.0.capacity(),
            capacity,
            "zeroize must keep the allocation"
        );
        let ptr = secret.0.as_ptr();
        // SAFETY: `secret` is alive and not mutated for the rest of this
        // function, the allocation spans `capacity` bytes, and every byte in
        // it was written by `zeroize` above, so the slice is initialized.
        let whole = unsafe { std::slice::from_raw_parts(ptr, capacity) };
        assert!(whole.iter().all(|&b| b == 0), "spare capacity not wiped");
    }

    // T2 (AC2)
    #[test]
    fn secret_value_is_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SecretValue>();
    }

    // T3 (AC3)
    #[test]
    fn fingerprint_known_answer_abc() {
        let secret = SecretValue::from("abc");
        assert_eq!(secret.fingerprint().as_str(), "sha256:ba7816bf8f01cfea");
    }

    // T3 (AC3)
    #[test]
    fn fingerprint_is_stable_across_constructions() {
        let a = SecretValue::from(String::from(PLAINTEXT));
        let b = SecretValue::from(PLAINTEXT.as_bytes().to_vec());
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_eq!(a.fingerprint(), Fingerprint::of(PLAINTEXT.as_bytes()));
    }

    // T5 (AC5)
    #[test]
    fn deserializes_from_json_string_field() {
        #[derive(Deserialize)]
        struct Finding {
            raw: SecretValue,
        }
        let finding: Finding = serde_json::from_str(r#"{"raw":"abc"}"#).unwrap();
        assert_eq!(finding.raw.expose_secret(|b| b.to_vec()), b"abc");
        assert!(finding.raw.expose_secret_str(|s| s == "abc").unwrap());
    }

    #[test]
    fn deserializes_escaped_json_string() {
        let secret: SecretValue = serde_json::from_str(r#""a\"b\\cé""#).unwrap();
        assert!(secret.expose_secret_str(|s| s == "a\"b\\c\u{e9}").unwrap());
    }

    #[test]
    fn deserialize_rejects_non_string() {
        let err = serde_json::from_str::<SecretValue>("42").unwrap_err();
        assert!(err.to_string().contains("a string holding a secret value"));
    }

    // T6 (AC6)
    #[test]
    fn eq_same_bytes() {
        assert_eq!(SecretValue::from("abc"), SecretValue::from("abc"));
    }

    // T6 (AC6)
    #[test]
    fn ne_different_length() {
        assert_ne!(SecretValue::from("abc"), SecretValue::from("abcd"));
        assert_ne!(SecretValue::from(""), SecretValue::from("a"));
    }

    // T6 (AC6)
    #[test]
    fn ne_same_length_different_byte() {
        assert_ne!(SecretValue::from("abc"), SecretValue::from("xbc"));
        assert_ne!(SecretValue::from("abc"), SecretValue::from("axc"));
    }

    // T6 (AC6)
    #[test]
    fn ne_differs_only_in_last_byte() {
        let a = SecretValue::from(vec![7u8; 1024]);
        let mut tail = vec![7u8; 1024];
        tail[1023] = 8;
        assert_ne!(a, SecretValue::from(tail));
    }

    #[test]
    fn from_reader_reads_all_bytes() {
        let secret = SecretValue::from_reader(&b"token\n"[..]).unwrap();
        assert_eq!(secret.len(), 6);
        assert!(!secret.is_empty());
        assert!(secret.expose_secret(|b| b == b"token\n"));

        let long = vec![b'x'; READ_RESERVE * 2 + 1];
        let secret = SecretValue::from_reader(long.as_slice()).unwrap();
        assert_eq!(secret.len(), long.len());
    }

    #[test]
    fn expose_secret_str_rejects_invalid_utf8() {
        let secret = SecretValue::from(vec![0xffu8, 0xfe]);
        assert!(secret.expose_secret_str(|_| ()).is_err());
    }

    #[test]
    fn clone_is_equal_and_independent() {
        let original = SecretValue::from(PLAINTEXT);
        let mut copy = original.clone();
        assert_eq!(original, copy);
        copy.zeroize();
        assert!(copy.is_empty());
        assert_eq!(original.len(), PLAINTEXT.len());
    }

    #[test]
    fn secret_pair_debug_hides_secret() {
        let pair = SecretPair::new("AKIAIOSFODNN7EXAMPLE", SecretValue::from(PLAINTEXT));
        let rendered = format!("{pair:?}");
        assert!(rendered.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(rendered.contains(pair.fingerprint().as_str()));
        assert!(!rendered.contains(PLAINTEXT));
        assert_eq!(pair.fingerprint(), pair.secret.fingerprint());
    }

    #[test]
    fn secret_pair_deserializes() {
        let pair: SecretPair =
            serde_json::from_str(r#"{"key_id":"AKIA1","secret":"s3cr3t"}"#).unwrap();
        assert_eq!(pair.key_id, "AKIA1");
        assert_eq!(pair.secret, SecretValue::from("s3cr3t"));
    }

    #[test]
    fn fingerprint_round_trips_through_serde() {
        let fp = SecretValue::from("abc").fingerprint();
        let json = serde_json::to_string(&fp).unwrap();
        assert_eq!(json, r#""sha256:ba7816bf8f01cfea""#);
        let back: Fingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(back, fp);
        assert_eq!(format!("{fp}"), format!("{fp:?}"));
    }

    #[test]
    fn fingerprint_rejects_malformed_text() {
        for bad in [
            "",
            "sha256:",
            "ba7816bf8f01cfea",
            "sha256:ba7816bf8f01cfe",
            "sha256:ba7816bf8f01cfeaa",
            "sha256:BA7816BF8F01CFEA",
            "md5:ba7816bf8f01cfea",
        ] {
            assert!(bad.parse::<Fingerprint>().is_err(), "accepted {bad:?}");
            assert!(serde_json::from_str::<Fingerprint>(&format!("{bad:?}")).is_err());
        }
        assert!("sha256:ba7816bf8f01cfea".parse::<Fingerprint>().is_ok());
    }
}
