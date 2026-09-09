//! Base64 that decodes *into* caller-owned locked memory.
//!
//! `Engine::decode` would hand back a fresh `Vec` on the normal heap, which is
//! precisely the allocation we cannot lock or reliably zero. `decode_slice`
//! writes into a buffer we already own, so a decrypted seed never touches a
//! page outside [`SecretBuffer`].

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

use crate::error::{Error, Result};
use crate::secret::SecretBuffer;

/// Upper bound on the decoded size of `encoded_len` base64 characters.
pub const fn max_decoded_len(encoded_len: usize) -> usize {
    encoded_len / 4 * 3 + 3
}

/// Decode standard (padded) base64 into `out`, appending to what is there.
pub fn decode_standard_into(
    encoded: &str,
    out: &mut SecretBuffer,
    context: &'static str,
) -> Result<()> {
    decode_with(&STANDARD, encoded, out, context)
}

/// Decode base64url without padding — the JWT segment encoding.
pub fn decode_url_nopad_into(
    encoded: &str,
    out: &mut SecretBuffer,
    context: &'static str,
) -> Result<()> {
    decode_with(&URL_SAFE_NO_PAD, encoded, out, context)
}

fn decode_with<E: Engine>(
    engine: &E,
    encoded: &str,
    out: &mut SecretBuffer,
    context: &'static str,
) -> Result<()> {
    let written = engine
        .decode_slice(encoded.as_bytes(), out.spare_mut())
        .map_err(|_| Error::MalformedBase64 { context })?;
    out.commit(written)
}

/// Encode to a plain `String`.
///
/// Only for values that are *not* secret: the KMS ciphertext and the AAD. Both
/// are safe on the ordinary heap — the ciphertext is useless without an
/// attested decrypt, and the AAD is authenticated but public. Never call this
/// on a plaintext seed.
pub fn encode_public(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Decode standard base64 onto the ordinary heap. Same rule as
/// [`encode_public`]: non-secret values only.
pub fn decode_public(encoded: &str, context: &'static str) -> Result<Vec<u8>> {
    STANDARD
        .decode(encoded)
        .map_err(|_| Error::MalformedBase64 { context })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_locked_memory() {
        let seed = [0x5Au8; 32];
        let encoded = encode_public(&seed);
        let mut out = SecretBuffer::new(max_decoded_len(encoded.len())).unwrap();
        decode_standard_into(&encoded, &mut out, "test").unwrap();
        assert_eq!(out.as_slice(), &seed);
    }

    #[test]
    fn rejects_invalid_base64() {
        let mut out = SecretBuffer::new(64).unwrap();
        assert!(matches!(
            decode_standard_into("not base64!!", &mut out, "test"),
            Err(Error::MalformedBase64 { context: "test" })
        ));
    }

    #[test]
    fn refuses_to_overflow_the_target_buffer() {
        // A hostile response claiming far more plaintext than we sized for
        // must error, not scribble past the allocation.
        let big = encode_public(&vec![0u8; 8192]);
        let mut out = SecretBuffer::new(32).unwrap();
        assert!(decode_standard_into(&big, &mut out, "test").is_err());
    }

    #[test]
    fn decodes_jwt_style_base64url() {
        let mut out = SecretBuffer::new(64).unwrap();
        // {"a":1} with no padding.
        decode_url_nopad_into("eyJhIjoxfQ", &mut out, "test").unwrap();
        assert_eq!(out.as_str().unwrap(), r#"{"a":1}"#);
    }
}
