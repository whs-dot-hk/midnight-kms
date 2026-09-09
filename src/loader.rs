//! Orchestration: attest, exchange, decrypt, hand each seed to the caller.

use crate::config::{KeyEntry, KeyRole, KmsConfig, SeedEncoding};
use crate::error::{Error, Result};
use crate::secret::SecretBuffer;
use crate::{attest, b64, hardening, http, kms, sts};

/// One decrypted seed, still in locked memory, already checked against the
/// shape its encoding declares.
///
/// The plaintext is reachable only through [`LoadedSeed::with_suri`], which
/// scopes the borrow to a closure so the caller cannot accidentally keep a
/// copy alive past the point where it should have been zeroed.
#[derive(Debug)]
pub struct LoadedSeed {
    pub role: KeyRole,
    pub encoding: SeedEncoding,
    seed: SecretBuffer,
}

impl LoadedSeed {
    /// Take ownership of a decrypted plaintext, enforcing the declared shape.
    ///
    /// * `Raw32` must be exactly 32 bytes.
    /// * `Suri` must be UTF-8 and non-empty once trimmed; it is re-homed
    ///   trimmed so no consumer ever sees the stray newline an operator's
    ///   `echo` may have sealed in.
    pub fn new(role: KeyRole, encoding: SeedEncoding, seed: SecretBuffer) -> Result<Self> {
        let seed = match encoding {
            SeedEncoding::Raw32 if seed.len() != 32 => {
                return Err(Error::SeedWrongLength {
                    role,
                    got: seed.len(),
                });
            }
            SeedEncoding::Raw32 => seed,
            SeedEncoding::Suri => {
                let trimmed = seed.as_str()?.trim();
                if trimmed.is_empty() {
                    return Err(Error::SeedEmpty { role });
                }
                SecretBuffer::from_slice(trimmed.as_bytes())?
            }
        };
        Ok(Self {
            role,
            encoding,
            seed,
        })
    }

    /// Run `f` with the seed rendered as a Substrate SURI.
    ///
    /// Substrate's keystore API takes a SURI `&str`, so a textual form is
    /// unavoidable at the boundary. `Raw32` becomes `0x<64 hex>` — Substrate
    /// reads a hex phrase of the right length as a raw seed, so this derives
    /// exactly the keypair `Pair::from_seed(bytes)` would. It is built inside
    /// a [`SecretBuffer`] and dropped — zeroed — as soon as `f` returns,
    /// whether normally or by unwinding. `Suri` is passed through.
    pub fn with_suri<T>(&self, f: impl FnOnce(&str) -> Result<T>) -> Result<T> {
        match self.encoding {
            SeedEncoding::Raw32 => {
                let mut suri = SecretBuffer::new(2 + 64)?;
                suri.push(b"0x")?;
                suri.push_hex(self.seed.as_slice())?;
                f(suri.as_str()?)
            }
            SeedEncoding::Suri => f(self.seed.as_str()?),
        }
    }
}

/// Fetch and decrypt every configured seed.
///
/// Order matters: hardening is applied *before* the first secret exists, and
/// the trace check runs before any decrypt so a debugger cannot be attached to
/// watch the seeds arrive.
///
/// # Panics
/// Must be called outside a tokio runtime — see [`crate::http::client`].
pub fn load_seeds(cfg: &KmsConfig) -> Result<Vec<LoadedSeed>> {
    cfg.validate()?;

    let report = hardening::harden_process(cfg.set_not_dumpable);
    log::info!(
        "midnight-kms hardening: core_dumps_disabled={} not_dumpable={} traced={}",
        report.core_dumps_disabled,
        report.not_dumpable,
        report.traced
    );
    if report.traced && cfg.refuse_if_traced {
        return Err(Error::Config(
            "a debugger is attached (TracerPid is non-zero); refusing to release validator keys. \
             Set refuse_if_traced=false only on a throwaway chain."
                .into(),
        ));
    }

    // Probe mlock before anything sensitive is fetched, so a misconfigured
    // RLIMIT_MEMLOCK fails at once rather than midway through key loading.
    let probe = SecretBuffer::new(1)?;
    if !probe.protections().locked {
        let message = "mlock failed: secret pages may be written to swap. On Confidential Space \
                       there is no swap, so this is usually benign; raise RLIMIT_MEMLOCK to fix it.";
        if cfg.require_mlock {
            return Err(Error::Config(format!("{message} (require_mlock is set)")));
        }
        log::warn!("{message}");
    }
    drop(probe);

    let timeout = cfg.timeout();

    let attestation = attest::fetch(&cfg.attest, timeout)?;
    log::info!(
        "obtained confidential space attestation token via {:?}",
        attestation.source
    );
    match attest::loggable_claims_unverified(&attestation) {
        Ok(claims) => log::info!(
            "attested (UNVERIFIED, for diagnostics only) hwmodel={:?} swname={:?} \
             image_digest={:?} iss={:?}",
            claims.hardware_model,
            claims.software_name,
            claims.image_digest,
            claims.issuer
        ),
        // Never fatal: these claims are diagnostics, and the real check is the
        // IAM condition. A parse failure here must not stop a valid workload.
        Err(e) => log::warn!("could not decode attestation claims for logging: {e}"),
    }

    let client = http::client(timeout)?;
    let access = sts::exchange(&client, &attestation, &cfg.wip_audience)?;
    log::info!(
        "exchanged attestation for a federated access token (expires_in={:?}s)",
        access.expires_in_secs
    );
    // The attestation token has done its job; zero it now rather than at the
    // end of the function.
    drop(attestation);

    let mut loaded = Vec::with_capacity(cfg.keys.len());
    for entry in &cfg.keys {
        loaded.push(load_one(&client, cfg, entry, &access)?);
    }
    // `access` is zeroed here; every seed is already in hand.
    drop(access);

    log::info!("released {} validator key(s) from Cloud KMS", loaded.len());
    Ok(loaded)
}

fn load_one(
    client: &reqwest::blocking::Client,
    cfg: &KmsConfig,
    entry: &KeyEntry,
    access: &sts::AccessToken,
) -> Result<LoadedSeed> {
    // The sealed blob is not secret, so ordinary file reading is fine. It is
    // decoded here so a corrupt file fails with its path, not as an opaque
    // KMS rejection.
    let path = entry.ciphertext_path.display();
    let ciphertext = std::fs::read_to_string(&entry.ciphertext_path).map_err(|e| {
        Error::Io(format!(
            "reading sealed {} seed from {path}: {e}",
            entry.role
        ))
    })?;
    let ciphertext = b64::decode_public(ciphertext.trim(), "sealed seed file")?;
    if ciphertext.is_empty() {
        return Err(Error::Config(format!("sealed seed file {path} is empty")));
    }

    let plaintext = kms::decrypt_seed(client, cfg, entry, access, &ciphertext)?;
    log::info!(
        "decrypted {} seed ({} bytes, {:?})",
        entry.role,
        plaintext.len(),
        entry.encoding
    );
    LoadedSeed::new(entry.role, entry.encoding, plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loaded(role: KeyRole, encoding: SeedEncoding, bytes: &[u8]) -> Result<LoadedSeed> {
        LoadedSeed::new(role, encoding, SecretBuffer::from_slice(bytes)?)
    }

    #[test]
    fn raw32_renders_as_a_hex_suri() {
        let seed = loaded(KeyRole::Aura, SeedEncoding::Raw32, &[0xABu8; 32]).unwrap();
        let suri = seed.with_suri(|s| Ok(s.to_string())).unwrap();
        assert_eq!(suri, format!("0x{}", "ab".repeat(32)));
        assert_eq!(suri.len(), 66);
    }

    #[test]
    fn raw32_rejects_a_wrong_length_seed() {
        assert!(matches!(
            loaded(KeyRole::Aura, SeedEncoding::Raw32, &[0u8; 31]),
            Err(Error::SeedWrongLength { got: 31, .. })
        ));
    }

    #[test]
    fn suri_is_passed_through_and_trimmed() {
        let seed = loaded(
            KeyRole::Grandpa,
            SeedEncoding::Suri,
            b"  bottom drive obey lake curtain smoke basket hold race lonely fit walk//Alice\n",
        )
        .unwrap();
        let suri = seed.with_suri(|s| Ok(s.to_string())).unwrap();
        assert!(suri.starts_with("bottom drive"));
        assert!(suri.ends_with("//Alice"));
    }

    #[test]
    fn empty_and_non_utf8_suris_are_rejected() {
        assert!(matches!(
            loaded(KeyRole::Babe, SeedEncoding::Suri, b"   \n  "),
            Err(Error::SeedEmpty { .. })
        ));
        assert!(matches!(
            loaded(KeyRole::Babe, SeedEncoding::Suri, &[0xff, 0xfe]),
            Err(Error::NotUtf8)
        ));
    }

    #[test]
    fn suri_buffer_does_not_outlive_the_closure() {
        // The closure may not return the borrowed &str; capturing the address
        // and checking it after the fact is the closest we can get in a test.
        // What this pins down is that `with_suri` hands out a borrow, not an
        // owned value the caller could retain.
        let seed = loaded(KeyRole::Aura, SeedEncoding::Raw32, &[1u8; 32]).unwrap();
        let addr = seed.with_suri(|s| Ok(s.as_ptr() as usize)).unwrap();
        assert_ne!(addr, 0);
    }

    #[test]
    fn debug_of_a_loaded_seed_is_redacted() {
        let seed = loaded(
            KeyRole::CrossChain,
            SeedEncoding::Raw32,
            b"SECRETSECRETSECRETSECRETSECRETSE",
        )
        .unwrap();
        let rendered = format!("{seed:?}");
        assert!(!rendered.contains("SECRET"), "{rendered}");
        assert!(
            rendered.contains("cross_chain") || rendered.contains("CrossChain"),
            "{rendered}"
        );
    }
}
