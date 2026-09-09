//! Configuration, and the AAD that binds each ciphertext to one specific use.

use core::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The four validator key roles midnight-node loads at startup, matching the
/// existing `*_seed_file` options in `node/src/cfg/midnight_cfg/mod.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRole {
    Aura,
    Babe,
    Grandpa,
    CrossChain,
}

impl KeyRole {
    /// Stable lowercase name. This goes into the AAD, so changing any of these
    /// strings makes every previously sealed blob undecryptable — treat them
    /// as a wire format.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aura => "aura",
            Self::Babe => "babe",
            Self::Grandpa => "grandpa",
            Self::CrossChain => "cross_chain",
        }
    }

    /// Substrate `KeyTypeId` bytes for this role.
    ///
    /// These match `sp_consensus_aura::KEY_TYPE`, `sp_consensus_babe::KEY_TYPE`,
    /// `sp_consensus_grandpa::KEY_TYPE` and the `KeyTypeId(*b"crch")` used
    /// literally in `node/src/command.rs`. Held here as bytes so the core
    /// crate needs no polkadot-sdk dependency.
    pub const fn key_type(self) -> [u8; 4] {
        match self {
            Self::Aura => *b"aura",
            Self::Babe => *b"babe",
            Self::Grandpa => *b"gran",
            Self::CrossChain => *b"crch",
        }
    }

    /// The signature scheme, which decides how a seed becomes a keypair.
    pub const fn scheme(self) -> Scheme {
        match self {
            // Aura and BABE authority keys are both sr25519.
            Self::Aura | Self::Babe => Scheme::Sr25519,
            Self::Grandpa => Scheme::Ed25519,
            Self::CrossChain => Scheme::Ecdsa,
        }
    }
}

impl fmt::Display for KeyRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Sr25519,
    Ed25519,
    Ecdsa,
}

/// How to interpret the decrypted plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeedEncoding {
    /// Exactly 32 raw bytes. Preferred: unambiguous, and no secret ever exists
    /// as human-readable text.
    Raw32,
    /// A UTF-8 Substrate SURI — a BIP39 phrase, optionally with a derivation
    /// path, or a `0x`-prefixed hex seed.
    ///
    /// Needed for compatibility, and it is not optional in practice: a
    /// validator already registered with a public key derived from a BIP39
    /// phrase **cannot** switch to `Raw32`. Substrate runs a phrase through
    /// PBKDF2, so `from_string(phrase)` and `from_seed(raw32)` yield different
    /// keypairs. Sealing the phrase's raw entropy as `Raw32` would silently
    /// produce a *different, wrong* authority key.
    Suri,
}

impl SeedEncoding {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Raw32 => "raw32",
            Self::Suri => "suri",
        }
    }
}

/// One sealed validator key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    pub role: KeyRole,

    /// Full Cloud KMS resource name:
    /// `projects/P/locations/L/keyRings/R/cryptoKeys/K`.
    pub kms_key: String,

    /// File holding the base64 KMS ciphertext. Not secret — it is useless
    /// without a decrypt that only an attested workload can obtain — so it can
    /// live on the boot disk, in a ConfigMap, or in metadata.
    pub ciphertext_path: PathBuf,

    pub encoding: SeedEncoding,

    /// Expected public key, hex, with or without `0x`.
    ///
    /// Strongly recommended. Public data, so it is safe in config, and it
    /// turns three otherwise-silent misconfigurations — swapped ciphertext
    /// blobs, a wrong role mapping, the `Suri`/`Raw32` mix-up above — into a
    /// loud startup failure instead of a validator that signs with the wrong
    /// key and gets slashed.
    #[serde(default)]
    pub expected_public_key: Option<String>,
}

/// Google's canonical endpoints. Pinned so that a compromised or mistaken
/// config cannot redirect an attestation token to an attacker-controlled host.
pub const STS_ENDPOINT: &str = "https://sts.googleapis.com/v1/token";
pub const KMS_ENDPOINT_BASE: &str = "https://cloudkms.googleapis.com/v1/";

/// The `aud` claim requested for every attestation token.
///
/// This is the audience the launcher puts on its pre-minted token file, and the
/// only value the workload identity pool provider in `terraform/kms_tee.tf`
/// lists in `allowed_audiences`. Requesting the same audience through the
/// socket keeps both token sources interchangeable at STS; which *pool* the
/// token is exchanged against is bound by the STS `audience` parameter, not by
/// this claim.
pub const ATTESTATION_AUDIENCE: &str = "https://sts.googleapis.com";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestConfig {
    /// Confidential Space launcher's token socket.
    #[serde(default = "default_socket")]
    pub socket_path: PathBuf,
    /// Fallback: the launcher also drops a default-audience OIDC token here.
    #[serde(default = "default_token_file")]
    pub token_file: PathBuf,
    /// Allow the file fallback at all. Turn off to require a freshly minted,
    /// audience-scoped token.
    #[serde(default = "default_true")]
    pub allow_token_file_fallback: bool,
}

fn default_socket() -> PathBuf {
    PathBuf::from("/run/container_launcher/teeserver.sock")
}
fn default_token_file() -> PathBuf {
    PathBuf::from("/run/container_launcher/attestation_verifier_claims_token")
}
fn default_true() -> bool {
    true
}

impl Default for AttestConfig {
    fn default() -> Self {
        Self {
            socket_path: default_socket(),
            token_file: default_token_file(),
            allow_token_file_fallback: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmsConfig {
    /// Workload identity pool provider, as the STS `audience`:
    /// `//iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>`
    pub wip_audience: String,

    /// Chain identifier, mixed into the AAD so a testnet blob cannot be
    /// replayed into a mainnet validator.
    pub chain_id: String,

    pub keys: Vec<KeyEntry>,

    #[serde(default)]
    pub attest: AttestConfig,

    /// Fail startup if `mlock` did not take effect. Default off: Confidential
    /// Space has no swap, so an unlocked page has nowhere durable to leak to,
    /// and a low `RLIMIT_MEMLOCK` should not brick a validator.
    #[serde(default)]
    pub require_mlock: bool,

    /// Apply `PR_SET_DUMPABLE = 0`. Blocks `/proc/<pid>/mem` reads by a
    /// same-uid process, at the cost of also blocking legitimate live
    /// debugging of the node.
    #[serde(default = "default_true")]
    pub set_not_dumpable: bool,

    /// Refuse to load keys while a debugger is attached.
    #[serde(default = "default_true")]
    pub refuse_if_traced: bool,

    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_timeout_secs() -> u64 {
    20
}

impl KmsConfig {
    /// Validate everything that can be checked without network access.
    ///
    /// Runs before the first token is minted so a typo fails immediately
    /// rather than after an attestation round trip.
    pub fn validate(&self) -> Result<()> {
        validate_audience(&self.wip_audience)?;

        // The chain id goes into a NUL-delimited AAD, so it must not itself
        // contain a delimiter or any control byte — otherwise two different
        // (chain, role) pairs could produce the same AAD.
        if self.chain_id.is_empty() || !is_aad_token_safe(&self.chain_id) {
            return Err(Error::Config(format!(
                "chain_id {:?} must be a non-empty string of [A-Za-z0-9._-]",
                self.chain_id
            )));
        }

        if self.keys.is_empty() {
            return Err(Error::Config("no keys configured for KMS release".into()));
        }

        let mut seen = Vec::new();
        for key in &self.keys {
            if seen.contains(&key.role) {
                return Err(Error::Config(format!(
                    "duplicate configuration for role {}",
                    key.role
                )));
            }
            seen.push(key.role);
            validate_kms_key_name(&key.kms_key)?;

            if let Some(pk) = &key.expected_public_key {
                let hex = pk.strip_prefix("0x").unwrap_or(pk);
                if hex.is_empty()
                    || hex.len() % 2 != 0
                    || !hex.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err(Error::Config(format!(
                        "expected_public_key for {} is not valid hex",
                        key.role
                    )));
                }
            }
        }

        if self.timeout_secs == 0 || self.timeout_secs > 300 {
            return Err(Error::Config("timeout_secs must be in 1..=300".into()));
        }
        Ok(())
    }

    /// `:decrypt` URL for a role's key, built from the pinned base so config
    /// cannot point it elsewhere.
    pub fn decrypt_url(&self, entry: &KeyEntry) -> String {
        format!("{KMS_ENDPOINT_BASE}{}:decrypt", entry.kms_key)
    }

    pub fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.timeout_secs)
    }
}

fn is_aad_token_safe(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// The workload identity pool audience is interpolated verbatim into the STS
/// request body, so it must be shape-checked and free of anything that could
/// break out of a JSON string.
pub(crate) fn validate_audience(audience: &str) -> Result<()> {
    const PREFIX: &str = "//iam.googleapis.com/projects/";
    if !audience.starts_with(PREFIX)
        || !audience.contains("/workloadIdentityPools/")
        || !audience.contains("/providers/")
    {
        return Err(Error::Config(format!(
            "wip_audience must look like \
             {PREFIX}<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>, \
             got {audience:?}"
        )));
    }
    // No control characters, no whitespace: this value is interpolated into a
    // JSON request body.
    if audience
        .bytes()
        .any(|b| b.is_ascii_control() || b == b'"' || b == b'\\' || b == b' ')
    {
        return Err(Error::Config(
            "wip_audience contains illegal characters".into(),
        ));
    }
    Ok(())
}

fn validate_kms_key_name(name: &str) -> Result<()> {
    let parts: Vec<&str> = name.split('/').collect();
    let shape_ok = parts.len() == 8
        && parts[0] == "projects"
        && parts[2] == "locations"
        && parts[4] == "keyRings"
        && parts[6] == "cryptoKeys"
        && parts[1..].iter().all(|p| !p.is_empty());
    if !shape_ok {
        return Err(Error::Config(format!(
            "kms_key must be projects/P/locations/L/keyRings/R/cryptoKeys/K, got {name:?}"
        )));
    }
    // Guards against path traversal or a query string being smuggled into the
    // URL we build in `decrypt_url`.
    if name
        .bytes()
        .any(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_')))
    {
        return Err(Error::Config(format!(
            "kms_key {name:?} contains illegal characters"
        )));
    }
    Ok(())
}

/// Additional authenticated data binding a ciphertext to exactly one
/// (version, chain, role, encoding).
///
/// Cloud KMS authenticates but does not encrypt the AAD, and decrypt fails
/// unless the same bytes are supplied. That converts three attacks into hard
/// errors:
///
/// * presenting the GRANDPA blob as the Aura seed, so the node signs Aura
///   blocks with the finality key;
/// * replaying a testnet blob at a mainnet validator that shares a key ring;
/// * flipping the declared encoding to change which keypair a seed derives.
///
/// Fields are NUL-delimited and validated to contain no NUL, so the encoding
/// is unambiguous. **These bytes are a wire format**: any change makes every
/// existing sealed blob undecryptable, so it is versioned.
pub fn aad(chain_id: &str, role: KeyRole, encoding: SeedEncoding) -> Vec<u8> {
    debug_assert!(
        is_aad_token_safe(chain_id),
        "chain_id must be validated before use"
    );
    let mut out = Vec::new();
    out.extend_from_slice(b"midnight-kms/v1");
    out.push(0);
    out.extend_from_slice(b"chain=");
    out.extend_from_slice(chain_id.as_bytes());
    out.push(0);
    out.extend_from_slice(b"role=");
    out.extend_from_slice(role.as_str().as_bytes());
    out.push(0);
    out.extend_from_slice(b"enc=");
    out.extend_from_slice(encoding.as_str().as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> KmsConfig {
        KmsConfig {
            wip_audience:
                "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/midnight-tee/providers/cs"
                    .into(),
            chain_id: "midnight-mainnet".into(),
            keys: vec![KeyEntry {
                role: KeyRole::Aura,
                kms_key:
                    "projects/p/locations/europe-west4/keyRings/validator/cryptoKeys/aura-seed"
                        .into(),
                ciphertext_path: "/etc/midnight/aura.seed.enc".into(),
                encoding: SeedEncoding::Raw32,
                expected_public_key: Some("0x".to_string() + &"ab".repeat(32)),
            }],
            attest: AttestConfig::default(),
            require_mlock: false,
            set_not_dumpable: true,
            refuse_if_traced: true,
            timeout_secs: 20,
        }
    }

    #[test]
    fn accepts_a_well_formed_config() {
        cfg().validate().unwrap();
    }

    #[test]
    fn rejects_bad_audience() {
        let mut c = cfg();
        c.wip_audience = "https://sts.googleapis.com".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_malformed_or_hostile_key_names() {
        for bad in [
            "projects/p/locations/l/keyRings/r/cryptoKeys", // too short
            "projects/p/locations/l/keyRings//cryptoKeys/k", // empty segment
            "projects/p/locations/l/keyRings/r/cryptoKeys/k?alt=json", // query smuggling
            "projects/p/locations/l/keyRings/r/cryptoKeys/../../../evil", // traversal
        ] {
            let mut c = cfg();
            c.keys[0].kms_key = bad.into();
            assert!(c.validate().is_err(), "should have rejected {bad}");
        }
    }

    #[test]
    fn rejects_duplicate_roles_and_bad_chain_ids() {
        let mut c = cfg();
        let dup = c.keys[0].clone();
        c.keys.push(dup);
        assert!(c.validate().is_err());

        let mut c = cfg();
        c.chain_id = "main\0net".into();
        assert!(c.validate().is_err());
        c.chain_id = String::new();
        assert!(c.validate().is_err());
    }

    #[test]
    fn decrypt_url_is_built_from_the_pinned_host() {
        let c = cfg();
        assert_eq!(
            c.decrypt_url(&c.keys[0]),
            "https://cloudkms.googleapis.com/v1/projects/p/locations/europe-west4/keyRings/validator/cryptoKeys/aura-seed:decrypt"
        );
    }

    #[test]
    fn aad_is_distinct_per_role_chain_and_encoding() {
        let a = aad("mainnet", KeyRole::Aura, SeedEncoding::Raw32);
        assert_eq!(
            a,
            b"midnight-kms/v1\0chain=mainnet\0role=aura\0enc=raw32".to_vec()
        );
        // Every axis must change the AAD.
        assert_ne!(a, aad("testnet", KeyRole::Aura, SeedEncoding::Raw32));
        assert_ne!(a, aad("mainnet", KeyRole::Babe, SeedEncoding::Raw32));
        assert_ne!(a, aad("mainnet", KeyRole::Aura, SeedEncoding::Suri));
    }

    #[test]
    fn aad_delimiters_cannot_be_confused() {
        // Without NUL-delimiting and chain_id validation, ("a", role=b) and
        // ("a\0role=b", ...) could collide. chain_id validation forbids the
        // delimiter outright, so no two inputs share an AAD.
        assert!(!is_aad_token_safe("a\0role=babe"));
        assert!(!is_aad_token_safe("a=b"));
        assert!(is_aad_token_safe("midnight-mainnet.02"));
    }

    #[test]
    fn key_type_ids_match_the_node() {
        assert_eq!(&KeyRole::Aura.key_type(), b"aura");
        assert_eq!(&KeyRole::Babe.key_type(), b"babe");
        assert_eq!(&KeyRole::Grandpa.key_type(), b"gran");
        assert_eq!(&KeyRole::CrossChain.key_type(), b"crch");
        assert_eq!(KeyRole::Grandpa.scheme(), Scheme::Ed25519);
        assert_eq!(KeyRole::CrossChain.scheme(), Scheme::Ecdsa);
    }
}
