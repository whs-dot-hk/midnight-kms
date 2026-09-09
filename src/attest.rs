//! Obtaining a Confidential Space attestation token.
//!
//! # What this token is
//!
//! Inside a Confidential Space VM, a launcher process outside the workload's
//! control measures the VM (AMD SEV-SNP report, firmware, image digest,
//! container signatures) and exchanges that measurement with Google's
//! attestation verifier for a short-lived OIDC token. The workload can ask for
//! a token but cannot influence its claims.
//!
//! # What this module is not
//!
//! It is **not** the security control. Nothing verified here keeps a key safe:
//! code running outside a TEE could return any bytes it liked from these
//! functions. The control is entirely server-side — the workload identity pool
//! provider validates the token's signature and claims, and the KMS IAM
//! condition releases `decrypt` only to a principal whose attested image
//! digest matches. See `terraform/kms_tee.tf`.
//!
//! The local checks here exist to *fail fast and legibly*: a validator that is
//! accidentally launched outside a TEE should say so at startup rather than
//! stall on an opaque `PERMISSION_DENIED` from KMS.

use std::io::Read;
use std::time::Duration;

use crate::config::{ATTESTATION_AUDIENCE, AttestConfig};
use crate::error::{Error, Result};
use crate::secret::{SecretBuffer, is_credential_safe};
use crate::{b64, uds};

/// Attestation tokens are a few KiB; this is generous headroom.
const MAX_TOKEN: usize = 32 * 1024;

/// A Confidential Space OIDC token with the `aud` claim
/// [`ATTESTATION_AUDIENCE`].
///
/// A bearer credential, so it lives in locked memory and is zeroed on drop.
/// Every constructor runs `validate_jwt_shape`, so holders may interpolate
/// the bytes into a JSON string or header without escaping.
#[derive(Debug)]
pub struct AttestationToken {
    pub(crate) token: SecretBuffer,
    pub source: TokenSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenSource {
    /// Freshly minted through the launcher socket with a nonce. Preferred.
    LauncherSocket,
    /// The launcher's pre-minted token file: same audience, but we cannot
    /// supply a nonce, so the token may be as old as the launcher's refresh
    /// interval.
    TokenFile,
}

impl AttestationToken {
    pub fn as_secret(&self) -> &SecretBuffer {
        &self.token
    }
}

/// Fetch a token from the launcher socket, or the token file if allowed.
pub fn fetch(cfg: &AttestConfig, timeout: Duration) -> Result<AttestationToken> {
    if cfg.socket_path.exists() {
        return fetch_from_socket(cfg, timeout);
    }
    if cfg.allow_token_file_fallback && cfg.token_file.exists() {
        log::warn!(
            "confidential space launcher socket {} is absent; falling back to the pre-minted \
             token file {}. No nonce is bound, so the token may not be fresh.",
            cfg.socket_path.display(),
            cfg.token_file.display()
        );
        return fetch_from_file(cfg);
    }
    Err(Error::NotInConfidentialSpace {
        socket: cfg.socket_path.display().to_string(),
        file: cfg.token_file.display().to_string(),
    })
}

fn fetch_from_socket(cfg: &AttestConfig, timeout: Duration) -> Result<AttestationToken> {
    // The nonce forces the launcher to mint a fresh token rather than serve a
    // cached one. Note honestly: STS does *not* validate it, so this buys
    // freshness and correlation, not authentication. It becomes load-bearing
    // only if a future verifier issues a challenge.
    let nonce = random_hex_nonce()?;

    // Both interpolated values are constants or hex, so this needs no escaping.
    let body = format!(
        r#"{{"audience":"{ATTESTATION_AUDIENCE}","nonces":["{nonce}"],"token_type":"OIDC"}}"#
    );

    let response = uds::post_json(&cfg.socket_path, "/v1/token", body.as_bytes(), timeout)?;
    if response.status != 200 {
        return Err(Error::AttestationTokenRejected {
            status: response.status,
        });
    }

    // This endpoint returns the raw JWT as the body, not JSON.
    let token = take_trimmed(response.body)?;
    validate_jwt_shape(&token)?;
    Ok(AttestationToken {
        token,
        source: TokenSource::LauncherSocket,
    })
}

fn fetch_from_file(cfg: &AttestConfig) -> Result<AttestationToken> {
    let mut file = std::fs::File::open(&cfg.token_file).map_err(|e| Error::Io(e.to_string()))?;
    let mut buf = SecretBuffer::new(MAX_TOKEN)?;
    buf.fill_from(&mut file)?;
    let token = take_trimmed(buf)?;
    validate_jwt_shape(&token)?;
    Ok(AttestationToken {
        token,
        source: TokenSource::TokenFile,
    })
}

/// Copy into a right-sized buffer with surrounding whitespace removed.
///
/// The token file ends with a newline, and a newline in an `Authorization`
/// header or a JSON string is exactly the injection we validate against later.
fn take_trimmed(buf: SecretBuffer) -> Result<SecretBuffer> {
    SecretBuffer::from_slice(buf.as_slice().trim_ascii())
}

/// Structural JWT check: three base64url segments, safe charset.
///
/// Deliberately does not verify the signature. Verifying it here would be
/// theatre — we would have to trust our own copy of Google's JWKS, fetched by
/// the same process an attacker would already control. The workload identity
/// pool does this verification where it counts.
fn validate_jwt_shape(token: &SecretBuffer) -> Result<()> {
    let bytes = token.as_slice();
    if bytes.is_empty() {
        return Err(Error::MalformedAttestationToken { reason: "empty" });
    }
    if !is_credential_safe(bytes) {
        return Err(Error::MalformedAttestationToken {
            reason: "contains characters that cannot appear in a JWT",
        });
    }
    let dots = bytes.iter().filter(|&&b| b == b'.').count();
    if dots != 2 {
        return Err(Error::MalformedAttestationToken {
            reason: "not three dot-separated segments",
        });
    }
    if bytes.split(|&b| b == b'.').any(|seg| seg.is_empty()) {
        return Err(Error::MalformedAttestationToken {
            reason: "empty JWT segment",
        });
    }
    Ok(())
}

/// Non-secret claims worth logging at startup.
#[derive(Debug, Default, Clone)]
pub struct LoggableClaims {
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub hardware_model: Option<String>,
    pub software_name: Option<String>,
    pub image_digest: Option<String>,
}

/// Decode the payload segment for logging.
///
/// **Unverified.** The signature is not checked, so nothing returned here may
/// be used for an access-control decision. It exists so that an operator
/// staring at a `PERMISSION_DENIED` can see which image digest the workload
/// actually attested as, and compare it with the digest pinned in the IAM
/// condition. That one log line turns the most common deployment failure from
/// a guessing game into a diff.
pub fn loggable_claims_unverified(token: &AttestationToken) -> Result<LoggableClaims> {
    let payload_b64 =
        token
            .token
            .as_str()?
            .split('.')
            .nth(1)
            .ok_or(Error::MalformedAttestationToken {
                reason: "missing payload segment",
            })?;

    let mut payload = SecretBuffer::new(b64::max_decoded_len(payload_b64.len()))?;
    b64::decode_url_nopad_into(payload_b64, &mut payload, "attestation token")?;

    #[derive(serde::Deserialize)]
    struct Claims {
        iss: Option<String>,
        aud: Option<serde_json::Value>,
        hwmodel: Option<String>,
        swname: Option<String>,
        submods: Option<Submods>,
    }
    #[derive(serde::Deserialize)]
    struct Submods {
        container: Option<Container>,
    }
    #[derive(serde::Deserialize)]
    struct Container {
        image_digest: Option<String>,
    }

    let claims: Claims =
        serde_json::from_slice(payload.as_slice()).map_err(|_| Error::MalformedResponse {
            context: "attestation token payload",
        })?;

    Ok(LoggableClaims {
        issuer: claims.iss,
        audience: match claims.aud {
            Some(serde_json::Value::String(s)) => Some(s),
            Some(serde_json::Value::Array(a)) => {
                a.first().and_then(|v| v.as_str()).map(str::to_string)
            }
            _ => None,
        },
        hardware_model: claims.hwmodel,
        software_name: claims.swname,
        image_digest: claims
            .submods
            .and_then(|s| s.container)
            .and_then(|c| c.image_digest),
    })
}

/// 32 hex characters from the kernel CSPRNG.
///
/// Reads `/dev/urandom` directly rather than adding a `rand` dependency for
/// one 16-byte draw. Confidential Space's length constraint on nonces is
/// 10..=74 bytes, which 32 satisfies.
fn random_hex_nonce() -> Result<String> {
    let mut raw = [0u8; 16];
    let mut f = std::fs::File::open("/dev/urandom").map_err(|e| Error::Io(e.to_string()))?;
    f.read_exact(&mut raw)
        .map_err(|e| Error::Io(e.to_string()))?;
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token_from(s: &str) -> AttestationToken {
        AttestationToken {
            token: SecretBuffer::from_slice(s.as_bytes()).unwrap(),
            source: TokenSource::LauncherSocket,
        }
    }

    #[test]
    fn accepts_a_well_formed_jwt() {
        validate_jwt_shape(&SecretBuffer::from_slice(b"aGVhZA.cGF5bG9hZA.c2ln").unwrap()).unwrap();
    }

    #[test]
    fn rejects_malformed_tokens() {
        for bad in [
            &b""[..],
            b"onlyonesegment",
            b"two.segments",
            b"four.seg.ments.here",
            b"head..sig",
            b"head.pay load.sig",
            b"head.pay\r\nload.sig",
            b"<html>not a token</html>",
        ] {
            let buf = SecretBuffer::from_slice(bad).unwrap();
            assert!(
                validate_jwt_shape(&buf).is_err(),
                "should have rejected {:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn errors_clearly_when_not_in_a_tee() {
        let cfg = AttestConfig {
            socket_path: "/nonexistent/teeserver.sock".into(),
            token_file: "/nonexistent/token".into(),
            allow_token_file_fallback: true,
        };
        let err = fetch(&cfg, Duration::from_secs(1)).unwrap_err();
        assert!(matches!(err, Error::NotInConfidentialSpace { .. }));
        // The message must name both paths so an operator can check them.
        let msg = err.to_string();
        assert!(msg.contains("teeserver.sock"), "{msg}");
    }

    #[test]
    fn nonce_is_hex_and_correctly_sized() {
        let a = random_hex_nonce().unwrap();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        // Two draws must differ, or it is not a nonce.
        assert_ne!(a, random_hex_nonce().unwrap());
    }

    #[test]
    fn extracts_claims_for_logging() {
        // {"iss":"https://confidentialcomputing.googleapis.com","aud":["x"],
        //  "hwmodel":"GCP_AMD_SEV","swname":"CONFIDENTIAL_SPACE",
        //  "submods":{"container":{"image_digest":"sha256:abc"}}}
        let payload = serde_json::json!({
            "iss": "https://confidentialcomputing.googleapis.com",
            "aud": ["//iam.googleapis.com/projects/1"],
            "hwmodel": "GCP_AMD_SEV",
            "swname": "CONFIDENTIAL_SPACE",
            "submods": {"container": {"image_digest": "sha256:abc123"}}
        })
        .to_string();
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            payload.as_bytes(),
        );
        let jwt = format!("aGVhZA.{encoded}.c2ln");

        let claims = loggable_claims_unverified(&token_from(&jwt)).unwrap();
        assert_eq!(claims.hardware_model.as_deref(), Some("GCP_AMD_SEV"));
        assert_eq!(claims.software_name.as_deref(), Some("CONFIDENTIAL_SPACE"));
        assert_eq!(claims.image_digest.as_deref(), Some("sha256:abc123"));
        assert_eq!(
            claims.audience.as_deref(),
            Some("//iam.googleapis.com/projects/1")
        );
    }

    #[test]
    fn claim_extraction_tolerates_unknown_shapes() {
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            br#"{"iss":"x"}"#,
        );
        let claims =
            loggable_claims_unverified(&token_from(&format!("aA.{encoded}.c2ln"))).unwrap();
        assert_eq!(claims.issuer.as_deref(), Some("x"));
        assert!(claims.image_digest.is_none());
    }

    #[test]
    fn trimming_removes_the_token_files_trailing_newline() {
        let buf = SecretBuffer::from_slice(b"  aGVhZA.cGF5.c2ln\n").unwrap();
        let trimmed = take_trimmed(buf).unwrap();
        assert_eq!(trimmed.as_slice(), b"aGVhZA.cGF5.c2ln");
        validate_jwt_shape(&trimmed).unwrap();
    }
}
