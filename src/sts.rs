//! Exchanging an attestation token for a Google access token (RFC 8693).
//!
//! The workload identity pool provider is where the attestation is actually
//! adjudicated: it verifies the token's signature against Google's attestation
//! verifier and applies the provider's attribute mapping and condition. If the
//! image digest, signer or TEE support attributes do not match, the exchange
//! fails here and no KMS call is ever made.

use std::io::Cursor;

use reqwest::blocking::{Body, Client};

use crate::attest::AttestationToken;
use crate::config::{STS_ENDPOINT, validate_audience};
use crate::error::{Error, Result};
use crate::http;
use crate::secret::{SecretBuffer, is_credential_safe};

/// STS responses are ~1 KiB; allow generous headroom for error envelopes.
const MAX_RESPONSE: usize = 16 * 1024;

/// A federated OAuth 2.0 access token. Short-lived, bearer, so it is held in
/// locked memory and zeroed on drop.
#[derive(Debug)]
pub struct AccessToken {
    token: SecretBuffer,
    pub expires_in_secs: Option<u64>,
}

impl AccessToken {
    pub fn as_secret(&self) -> &SecretBuffer {
        &self.token
    }
}

/// Exchange the attestation token. The deadline comes from the client built
/// by [`crate::http::client`], not from a separate argument.
pub fn exchange(
    client: &Client,
    attestation: &AttestationToken,
    audience: &str,
) -> Result<AccessToken> {
    let body = build_request_body(attestation, audience)?;
    let len = body.len() as u64;

    // Streamed out of the locked buffer, which reqwest drops — and so zeroes —
    // after sending. `.body(Vec<u8>)` would have made an unzeroable copy of
    // the attestation JWT on the ordinary heap first.
    let response = client
        .post(STS_ENDPOINT)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(Body::sized(Cursor::new(body), len))
        .send()
        .map_err(|e| http::transport_error("sts token exchange", &e))?;

    let status = response.status().as_u16();
    let raw = http::read_body(response, MAX_RESPONSE)?;

    if !(200..300).contains(&status) {
        return Err(Error::StsRejected {
            status,
            message: http::error_message(raw.as_slice()),
        });
    }
    parse_response(&raw)
}

/// Build the token-exchange JSON.
///
/// Hand-assembled inside a [`SecretBuffer`] rather than via `serde_json`,
/// because the body embeds the attestation JWT — a bearer credential.
/// `serde_json::to_vec` would place a plaintext copy on the ordinary heap
/// where it could neither be locked nor zeroed.
///
/// Safe without an escaping routine because both interpolated values are
/// charset-validated: the JWT at construction of [`AttestationToken`], the
/// audience by [`validate_audience`] here.
fn build_request_body(attestation: &AttestationToken, audience: &str) -> Result<SecretBuffer> {
    validate_audience(audience)?;
    let jwt = attestation.as_secret();

    let mut body = SecretBuffer::new(jwt.len() + audience.len() + 512)?;
    body.push(br#"{"audience":""#)?;
    body.push(audience.as_bytes())?;
    body.push(br#"","grantType":"urn:ietf:params:oauth:grant-type:token-exchange""#)?;
    body.push(br#","requestedTokenType":"urn:ietf:params:oauth:token-type:access_token""#)?;
    body.push(br#","subjectTokenType":"urn:ietf:params:oauth:token-type:jwt""#)?;
    // cloud-platform is the narrowest scope that covers cloudkms.decrypt;
    // the effective permission is bounded by the IAM condition, not this.
    body.push(br#","scope":"https://www.googleapis.com/auth/cloud-platform""#)?;
    body.push(br#","subjectToken":""#)?;
    body.push(jwt.as_slice())?;
    body.push(br#""}"#)?;
    Ok(body)
}

fn parse_response(raw: &SecretBuffer) -> Result<AccessToken> {
    // `Cow<'_, str>` borrows straight out of `raw`'s locked pages when the
    // JSON contains no escapes, which for an OAuth token it never does. That
    // keeps the access token from being copied onto the ordinary heap by
    // serde. It degrades to an owned `String` only if escapes appear.
    #[derive(serde::Deserialize)]
    struct StsResponse<'a> {
        #[serde(borrow, default)]
        access_token: Option<std::borrow::Cow<'a, str>>,
        #[serde(default)]
        expires_in: Option<u64>,
    }

    let parsed: StsResponse<'_> = serde_json::from_slice(raw.as_slice())
        .map_err(|_| Error::MalformedResponse { context: "sts" })?;

    let token_str = parsed.access_token.ok_or(Error::StsNoToken)?;
    if token_str.is_empty() {
        return Err(Error::StsNoToken);
    }
    if !is_credential_safe(token_str.as_bytes()) {
        return Err(Error::UnsafeCredential { context: "sts" });
    }

    let token = SecretBuffer::from_slice(token_str.as_bytes())?;
    Ok(AccessToken {
        token,
        expires_in_secs: parsed.expires_in,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::TokenSource;

    fn attestation(jwt: &str) -> AttestationToken {
        AttestationToken {
            token: SecretBuffer::from_slice(jwt.as_bytes()).unwrap(),
            source: TokenSource::LauncherSocket,
        }
    }

    const AUD: &str =
        "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/v";

    #[test]
    fn body_is_valid_json_and_carries_the_right_grant() {
        let body = build_request_body(&attestation("aGVhZA.cGF5.c2ln"), AUD).unwrap();
        let json: serde_json::Value = serde_json::from_slice(body.as_slice()).unwrap();
        assert_eq!(json["audience"], AUD);
        assert_eq!(
            json["grantType"],
            "urn:ietf:params:oauth:grant-type:token-exchange"
        );
        assert_eq!(
            json["subjectTokenType"],
            "urn:ietf:params:oauth:token-type:jwt"
        );
        assert_eq!(
            json["requestedTokenType"],
            "urn:ietf:params:oauth:token-type:access_token"
        );
        assert_eq!(json["subjectToken"], "aGVhZA.cGF5.c2ln");
    }

    #[test]
    fn body_construction_refuses_an_unsafe_audience() {
        let att = attestation("aGVhZA.cGF5.c2ln");
        let injected = format!(r#"{AUD}","x":"y"#);
        assert!(matches!(
            build_request_body(&att, &injected),
            Err(Error::Config(_))
        ));
    }

    #[test]
    fn parses_a_successful_exchange() {
        let raw = SecretBuffer::from_slice(
            br#"{"access_token":"ya29.a0AfB_byC-123","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600}"#,
        )
        .unwrap();
        let token = parse_response(&raw).unwrap();
        assert_eq!(token.as_secret().as_slice(), b"ya29.a0AfB_byC-123");
        assert_eq!(token.expires_in_secs, Some(3600));
    }

    #[test]
    fn rejects_responses_without_a_token() {
        for body in [
            &br#"{"token_type":"Bearer"}"#[..],
            br#"{"access_token":""}"#,
        ] {
            let raw = SecretBuffer::from_slice(body).unwrap();
            assert!(matches!(parse_response(&raw), Err(Error::StsNoToken)));
        }
    }

    #[test]
    fn rejects_a_token_that_could_inject_a_header() {
        let raw = SecretBuffer::from_slice(br#"{"access_token":"tok\r\nX-Evil: 1"}"#).unwrap();
        assert!(matches!(
            parse_response(&raw),
            Err(Error::UnsafeCredential { context: "sts" })
        ));
    }

    #[test]
    fn rejects_malformed_json() {
        let raw = SecretBuffer::from_slice(b"<html>502</html>").unwrap();
        assert!(matches!(
            parse_response(&raw),
            Err(Error::MalformedResponse { context: "sts" })
        ));
    }
}
