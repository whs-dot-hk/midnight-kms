//! Hardened blocking HTTPS client, and body reads that land in locked memory.
//!
//! Blocking on purpose: midnight-node loads validator keys during startup,
//! before the tokio runtime is handed to the service, so there is no runtime
//! to await on. `reqwest::blocking` panics if constructed *inside* a runtime —
//! see the note on [`client`].

use std::time::Duration;

use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderMap, HeaderValue};

use crate::error::{Error, Result};
use crate::secret::{SecretBuffer, is_credential_safe};

/// Build the client used for both STS and KMS.
///
/// Each setting closes something specific:
///
/// * `redirect(none)` — **the important one.** We send a bearer token on every
///   request. Following a redirect would forward that `Authorization` header,
///   or the attestation JWT in the STS body, to whatever host the redirect
///   named. A 3xx from these endpoints is now an error instead of an
///   exfiltration primitive.
/// * `https_only` — no silent downgrade to cleartext.
/// * `no_proxy` — ignore `HTTPS_PROXY`/`ALL_PROXY` from the environment.
///   Whoever sets an env var should not be able to interpose on the key
///   release path or learn its timing and size profile.
/// * `min_tls_version(1.2)` — floor, independent of future rustls defaults.
/// * timeouts — a hung metadata server must not wedge validator startup.
///
/// # Panics
/// Must not be called from inside a tokio runtime.
pub fn client(timeout: Duration) -> Result<Client> {
    Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(timeout)
        .connect_timeout(timeout)
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .user_agent(concat!("midnight-kms/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| Error::Io(format!("building https client: {e}")))
}

/// `Authorization: Bearer <token>` from a secret buffer.
///
/// The token's charset is validated first, so it cannot contain CR/LF and
/// therefore cannot inject a second header. The value is marked sensitive so
/// layers that redact headers will redact this one.
///
/// Residual: `HeaderValue` owns a copy on the ordinary heap that we cannot
/// zero. Access tokens are short-lived and this is noted in the README's
/// residual-exposure section.
pub fn bearer_header(token: &SecretBuffer, context: &'static str) -> Result<HeaderMap> {
    if !is_credential_safe(token.as_slice()) {
        return Err(Error::UnsafeCredential { context });
    }
    let mut buf = SecretBuffer::new(token.len() + 8)?;
    buf.push(b"Bearer ")?;
    buf.push(token.as_slice())?;

    let mut value =
        HeaderValue::from_bytes(buf.as_slice()).map_err(|_| Error::UnsafeCredential { context })?;
    value.set_sensitive(true);

    let mut headers = HeaderMap::new();
    headers.insert(reqwest::header::AUTHORIZATION, value);
    Ok(headers)
}

/// Read a response body into `capacity` bytes of locked memory.
///
/// Streams via `Read` rather than calling `.text()` or `.bytes()`, both of
/// which buffer the whole body inside reqwest first. Those buffers are
/// reference-counted `Bytes` with no zeroing hook, so for a response that
/// contains a decrypted seed they would be a plaintext copy we could never
/// clean up.
pub fn read_body(mut response: Response, capacity: usize) -> Result<SecretBuffer> {
    let mut buf = SecretBuffer::new(capacity)?;
    buf.fill_from(&mut response)?;
    Ok(buf)
}

/// A transport failure, reduced to its kind and the URL.
///
/// `reqwest::Error`'s `Display` never includes the request body, but it is not
/// under our control; keeping the message to the kind and the (fixed,
/// non-secret) URL means a future reqwest change cannot start logging a token.
pub fn transport_error(what: &str, e: &reqwest::Error) -> Error {
    let kind = if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connect"
    } else if e.is_redirect() {
        // A redirect would have forwarded the bearer token; the policy refused it.
        "unexpected redirect (refused)"
    } else if e.is_request() {
        "request"
    } else {
        "transport"
    };
    match e.url() {
        Some(url) => Error::Io(format!("{what}: {kind} error talking to {url}")),
        None => Error::Io(format!("{what}: {kind} error")),
    }
}

/// Pull a loggable message out of a Google API error envelope.
///
/// Never returns the raw body. Google's `error.message` is genuinely useful
/// here — "Decryption failed: the AAD provided does not match", "Permission
/// denied on resource" — and is written by the service, not by us, but it is
/// still sanitised: control characters stripped so it cannot forge log lines,
/// and length-capped.
pub fn error_message(body: &[u8]) -> String {
    #[derive(serde::Deserialize)]
    struct Envelope {
        error: Option<Inner>,
    }
    #[derive(serde::Deserialize)]
    struct Inner {
        message: Option<String>,
        status: Option<String>,
    }

    let raw = serde_json::from_slice::<Envelope>(body)
        .ok()
        .and_then(|e| e.error)
        .and_then(|i| i.message.or(i.status))
        .unwrap_or_else(|| "<no message in response>".to_string());

    let sanitised: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(400)
        .collect();
    sanitised.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_client() {
        client(Duration::from_secs(5)).unwrap();
    }

    #[test]
    fn bearer_header_is_marked_sensitive() {
        let token = SecretBuffer::from_slice(b"ya29.abcDEF-_123").unwrap();
        let headers = bearer_header(&token, "test").unwrap();
        let value = headers.get(reqwest::header::AUTHORIZATION).unwrap();
        assert!(value.is_sensitive());
        assert_eq!(value.as_bytes(), b"Bearer ya29.abcDEF-_123");
    }

    #[test]
    fn bearer_header_rejects_injection() {
        let token = SecretBuffer::from_slice(b"tok\r\nX-Evil: yes").unwrap();
        assert!(matches!(
            bearer_header(&token, "test"),
            Err(Error::UnsafeCredential { .. })
        ));
    }

    #[test]
    fn extracts_and_sanitises_google_error_messages() {
        let body = br#"{"error":{"code":400,"message":"Decryption failed: the AAD provided does not match","status":"INVALID_ARGUMENT"}}"#;
        assert_eq!(
            error_message(body),
            "Decryption failed: the AAD provided does not match"
        );

        // Falls back to status when there is no message.
        assert_eq!(
            error_message(br#"{"error":{"status":"PERMISSION_DENIED"}}"#),
            "PERMISSION_DENIED"
        );

        // Non-JSON bodies are never echoed.
        let html = b"<html><body>proxy error, token=hunter2</body></html>";
        assert_eq!(error_message(html), "<no message in response>");

        // Control characters cannot be used to forge extra log lines.
        let forged = br#"{"error":{"message":"ok\nERROR fake log line"}}"#;
        let msg = error_message(forged);
        assert!(!msg.contains('\n'), "{msg}");
    }

    #[test]
    fn error_message_is_length_capped() {
        let long = "A".repeat(5000);
        let body = format!(r#"{{"error":{{"message":"{long}"}}}}"#);
        assert!(error_message(body.as_bytes()).len() <= 400);
    }
}
