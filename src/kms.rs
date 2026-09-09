//! Cloud KMS symmetric decrypt.
//!
//! # Why decrypt, and not sign
//!
//! The obvious design — keep the key in KMS and ask it to sign — is not
//! available. Aura and BABE authority keys are **sr25519**, which Cloud KMS
//! does not implement (its asymmetric signing is RSA and ECDSA, plus Ed25519).
//! A remote signer is therefore impossible for the two consensus keys, and a
//! design that put only GRANDPA and the cross-chain key in a signer would
//! leave the block-production key exposed anyway.
//!
//! So the private key must exist in the node's address space, and the question
//! becomes *who is allowed to obtain it*. That is what attestation-gated
//! release answers.
//!
//! # No local envelope layer, on purpose
//!
//! A 32-byte seed fits comfortably in KMS's 64 KiB `encrypt` limit, so it is
//! encrypted directly under the KMS key. The alternative — wrapping a local
//! DEK and doing AES-GCM here — would add nonce management, a DEK lifetime and
//! a hand-written AEAD call path for no security gain: the DEK would be
//! exactly as sensitive as the seed, and would arrive over the same channel.
//! `additionalAuthenticatedData` gives the domain separation that would have
//! been the only real reason to build an envelope.

use reqwest::blocking::Client;

use crate::config::{KeyEntry, KeyRole, KmsConfig};
use crate::crc32c::crc32c;
use crate::error::{Error, Result};
use crate::secret::SecretBuffer;
use crate::sts::AccessToken;
use crate::{b64, config, http};

/// Ceiling on a decrypt response. A 32-byte seed base64s to 44 characters; a
/// long SURI to a few hundred. 8 KiB is generous and bounds how much locked
/// memory a hostile response can demand.
const MAX_RESPONSE: usize = 8 * 1024;

/// Largest plaintext we will accept, independent of the response size.
const MAX_PLAINTEXT: usize = 4096;

/// Decrypt one sealed seed. The returned buffer holds the plaintext.
pub fn decrypt_seed(
    client: &Client,
    cfg: &KmsConfig,
    entry: &KeyEntry,
    access: &AccessToken,
    ciphertext: &[u8],
) -> Result<SecretBuffer> {
    let aad = config::aad(&cfg.chain_id, entry.role, entry.encoding);
    let body = build_request(ciphertext, &aad);

    let headers = http::bearer_header(access.as_secret(), "kms")?;
    let response = client
        .post(cfg.decrypt_url(entry))
        .headers(headers)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .map_err(|e| http::transport_error("kms decrypt", &e))?;

    let status = response.status().as_u16();
    let raw = http::read_body(response, MAX_RESPONSE)?;

    if !(200..300).contains(&status) {
        return Err(Error::KmsRejected {
            role: entry.role,
            status,
            message: http::error_message(raw.as_slice()),
        });
    }
    parse_decrypt_response(&raw, entry.role)
}

/// Build the `:decrypt` request body.
///
/// Everything here is non-secret — ciphertext is useless without an attested
/// decrypt, and the AAD is authenticated but public — so it lives on the
/// ordinary heap. Every interpolated value is base64 or decimal, so no JSON
/// escaping is needed.
///
/// Both checksums are sent so KMS rejects a request corrupted in transit
/// rather than returning garbage. Google serialises int64 fields as JSON
/// strings, hence the quoting.
fn build_request(ciphertext: &[u8], aad: &[u8]) -> String {
    format!(
        r#"{{"ciphertext":"{}","ciphertextCrc32c":"{}","additionalAuthenticatedData":"{}","additionalAuthenticatedDataCrc32c":"{}"}}"#,
        b64::encode_public(ciphertext),
        crc32c(ciphertext),
        b64::encode_public(aad),
        crc32c(aad),
    )
}

fn parse_decrypt_response(raw: &SecretBuffer, role: KeyRole) -> Result<SecretBuffer> {
    // Borrowed `Cow` keeps the base64 plaintext from being copied onto the
    // ordinary heap by serde; it points into `raw`'s locked pages.
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DecryptResponse<'a> {
        #[serde(borrow, default)]
        plaintext: Option<std::borrow::Cow<'a, str>>,
        #[serde(borrow, default)]
        plaintext_crc32c: Option<std::borrow::Cow<'a, str>>,
    }

    let parsed: DecryptResponse<'_> =
        serde_json::from_slice(raw.as_slice()).map_err(|_| Error::MalformedResponse {
            context: "kms decrypt",
        })?;

    let plaintext_b64 = parsed.plaintext.ok_or(Error::MalformedResponse {
        context: "kms decrypt",
    })?;

    let decoded_bound = b64::max_decoded_len(plaintext_b64.len());
    if decoded_bound > MAX_PLAINTEXT {
        return Err(Error::SecretTooLarge {
            requested: decoded_bound,
            max: MAX_PLAINTEXT,
        });
    }

    let mut plaintext = SecretBuffer::new(decoded_bound.max(1))?;
    b64::decode_standard_into(&plaintext_b64, &mut plaintext, "kms decrypt")?;

    // Verify the checksum KMS computed over the plaintext.
    //
    // This is required, not optional: Google documents that a response whose
    // checksum does not match must be treated as corrupt. Skipping it would
    // let a single flipped bit in transit become a *silently wrong seed*, and
    // a wrong Aura seed means a validator that signs nothing anyone accepts.
    let expected_str = parsed
        .plaintext_crc32c
        .ok_or(Error::MissingPlaintextChecksum { role })?;
    let expected: u32 = expected_str.parse().map_err(|_| Error::MalformedResponse {
        context: "kms decrypt",
    })?;
    let computed = crc32c(plaintext.as_slice());
    if computed != expected {
        // `plaintext` is dropped — and therefore zeroed — on this return.
        return Err(Error::PlaintextCorrupt {
            role,
            expected,
            computed,
        });
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SeedEncoding;

    #[test]
    fn request_carries_ciphertext_aad_and_both_checksums() {
        let aad = config::aad("mainnet", KeyRole::Aura, SeedEncoding::Raw32);
        let body = build_request(b"pretend-ciphertext", &aad);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(
            json["ciphertext"],
            b64::encode_public(b"pretend-ciphertext")
        );
        assert_eq!(
            json["additionalAuthenticatedData"],
            b64::encode_public(&aad)
        );
        // int64 fields must be strings, per Google's JSON mapping.
        assert!(json["ciphertextCrc32c"].is_string());
        assert_eq!(
            json["ciphertextCrc32c"].as_str().unwrap(),
            crc32c(b"pretend-ciphertext").to_string()
        );
        assert_eq!(
            json["additionalAuthenticatedDataCrc32c"].as_str().unwrap(),
            crc32c(&aad).to_string()
        );
    }

    fn response_for(plaintext: &[u8]) -> SecretBuffer {
        let body = serde_json::json!({
            "plaintext": b64::encode_public(plaintext),
            "plaintextCrc32c": crc32c(plaintext).to_string(),
            "protectionLevel": "SOFTWARE",
        })
        .to_string();
        SecretBuffer::from_slice(body.as_bytes()).unwrap()
    }

    #[test]
    fn parses_a_valid_decrypt_response() {
        let seed = [0x42u8; 32];
        let out = parse_decrypt_response(&response_for(&seed), KeyRole::Aura).unwrap();
        assert_eq!(out.as_slice(), &seed);
        // The seed must have landed in locked, non-dumpable memory.
        let p = out.protections();
        assert!(
            p.locked || p.no_dump,
            "expected at least one protection to apply"
        );
    }

    #[test]
    fn rejects_a_corrupted_plaintext() {
        let seed = [0x42u8; 32];
        let body = serde_json::json!({
            "plaintext": b64::encode_public(&seed),
            // Checksum of different bytes: simulates in-transit corruption.
            "plaintextCrc32c": crc32c(b"something else").to_string(),
        })
        .to_string();
        let raw = SecretBuffer::from_slice(body.as_bytes()).unwrap();
        let err = parse_decrypt_response(&raw, KeyRole::Grandpa).unwrap_err();
        assert!(matches!(
            err,
            Error::PlaintextCorrupt {
                role: KeyRole::Grandpa,
                ..
            }
        ));
    }

    #[test]
    fn refuses_a_response_with_no_checksum() {
        // Never accept an unverified seed just because the field is absent.
        let body = serde_json::json!({ "plaintext": b64::encode_public(&[1u8; 32]) }).to_string();
        let raw = SecretBuffer::from_slice(body.as_bytes()).unwrap();
        assert!(matches!(
            parse_decrypt_response(&raw, KeyRole::Aura),
            Err(Error::MissingPlaintextChecksum { .. })
        ));
    }

    #[test]
    fn rejects_oversized_plaintext() {
        let huge = vec![0u8; MAX_PLAINTEXT + 64];
        assert!(matches!(
            parse_decrypt_response(&response_for(&huge), KeyRole::Aura),
            Err(Error::SecretTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_malformed_bodies() {
        for body in [&b"{}"[..], b"not json", br#"{"plaintext":"!!!!"}"#] {
            let raw = SecretBuffer::from_slice(body).unwrap();
            assert!(parse_decrypt_response(&raw, KeyRole::Aura).is_err());
        }
    }

    #[test]
    fn aad_mismatch_is_what_stops_a_swapped_blob() {
        // Documents the invariant the AAD enforces server-side: the bytes we
        // send for role=aura differ from those for role=grandpa, so a blob
        // sealed for one cannot be decrypted as the other.
        let a = config::aad("mainnet", KeyRole::Aura, SeedEncoding::Raw32);
        let g = config::aad("mainnet", KeyRole::Grandpa, SeedEncoding::Raw32);
        assert_ne!(crc32c(&a), crc32c(&g));
        assert_ne!(a, g);
    }
}
