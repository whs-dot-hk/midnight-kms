//! Error type.
//!
//! Invariant: no variant carries key material, and no variant carries a raw
//! HTTP response body. Errors are logged by the node at startup, so anything
//! reachable from here must be safe to write to a log aggregator.

use crate::config::KeyRole;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("allocation of locked secret memory failed")]
    Alloc,

    #[error("secret of {requested} bytes exceeds the {max} byte cap")]
    SecretTooLarge { requested: usize, max: usize },

    #[error("value does not fit in its {capacity} byte fixed-capacity secret buffer")]
    SecretCapacityExceeded { capacity: usize },

    #[error("secret is not valid UTF-8")]
    NotUtf8,

    #[error("i/o error: {0}")]
    Io(String),

    #[error("configuration error: {0}")]
    Config(String),

    // --- attestation ---
    #[error(
        "not running in a Confidential Space TEE: neither the launcher socket {socket} nor the \
         token file {file} is present"
    )]
    NotInConfidentialSpace { socket: String, file: String },

    #[error("the Confidential Space launcher returned HTTP {status} for the token request")]
    AttestationTokenRejected { status: u16 },

    #[error("the attestation token is not a well-formed JWT ({reason})")]
    MalformedAttestationToken { reason: &'static str },

    // --- token exchange ---
    #[error("STS token exchange failed with HTTP {status}: {message}")]
    StsRejected { status: u16, message: String },

    #[error("STS response did not contain an access token")]
    StsNoToken,

    // --- KMS ---
    #[error("Cloud KMS decrypt of the {role} seed failed with HTTP {status}: {message}")]
    KmsRejected {
        role: KeyRole,
        status: u16,
        message: String,
    },

    #[error(
        "Cloud KMS plaintext failed its CRC32C check for the {role} seed (expected {expected}, \
         computed {computed}) — the response was corrupted in transit"
    )]
    PlaintextCorrupt {
        role: KeyRole,
        expected: u32,
        computed: u32,
    },

    #[error("Cloud KMS did not echo a plaintext checksum for the {role} seed")]
    MissingPlaintextChecksum { role: KeyRole },

    #[error("malformed JSON in the {context} response")]
    MalformedResponse { context: &'static str },

    #[error("base64 in the {context} response is invalid")]
    MalformedBase64 { context: &'static str },

    #[error(
        "a credential returned by {context} contains characters that cannot appear in a bearer \
         token; refusing to use it"
    )]
    UnsafeCredential { context: &'static str },

    // --- seed shape ---
    #[error("the {role} seed decrypted to {got} bytes, but raw32 encoding requires exactly 32")]
    SeedWrongLength { role: KeyRole, got: usize },

    #[error("the {role} seed is empty after decryption")]
    SeedEmpty { role: KeyRole },

    #[error(
        "the {role} key derived public key {derived}, but the configured expected_public_key is \
         {expected} — wrong ciphertext blob, wrong role mapping, or wrong seed encoding"
    )]
    PublicKeyMismatch {
        role: KeyRole,
        derived: String,
        expected: String,
    },

    #[error("{role}: {message}")]
    Keystore { role: KeyRole, message: String },
}
