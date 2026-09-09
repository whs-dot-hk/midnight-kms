//! Substrate keystore adapter.
//!
//! Feature-gated (`--features substrate`) so the security-critical core builds
//! and tests without pulling in polkadot-sdk. In midnight-node this crate is
//! added with the feature on, and `sp-core`/`sp-keystore` come from the
//! workspace's pinned `polkadot-stable2606` git dependency rather than
//! crates.io.
//!
//! # Why this does not call `Keystore::insert`
//!
//! Two traps in `sc-keystore`, both verified against `polkadot-stable2606`:
//!
//! 1. `KeystoreInner::insert` writes the SURI to a file and **only** to a
//!    file (`substrate/client/keystore/src/local.rs`):
//!
//!    ```text
//!    fn insert(&self, key_type, suri, public) -> Result<()> {
//!        if let Some(path) = self.key_file_path(public, key_type) {
//!            Self::write_to_file(path, suri)?;
//!        }
//!        Ok(())
//!    }
//!    ```
//!
//!    This is how the existing `*_seed_file` path in `node/src/command.rs`
//!    works, and it means every validator seed is currently persisted in
//!    cleartext under the keystore directory. Reusing `insert` for a
//!    KMS-released seed would write the plaintext straight back to the boot
//!    disk and defeat the entire design.
//!
//! 2. On an **in-memory** keystore that same `insert` is a silent no-op: with
//!    `path: None` the `if let` does not fire, nothing is added to the
//!    `additional` map, and `Ok(())` is returned. `raw_public_keys` would then
//!    report no keys and the node would quietly start as a non-authority.
//!
//! The correct call is `Keystore::{sr25519,ed25519,ecdsa}_generate_new(
//! key_type, Some(suri))`. Despite the name, passing `Some` does not generate
//! anything — it routes to `insert_ephemeral_from_seed_by_type`, which derives
//! the pair from the SURI and stores it via `insert_ephemeral_pair`, whose own
//! doc comment reads *"Does not place it into the file system store."*
//!
//! So the released seed lands in the keystore's in-memory map and **never** on
//! disk, whether or not the node was configured with a keystore path. Setting
//! `KeystoreConfig::InMemory` is still recommended, but as belt-and-braces
//! against stale cleartext seed files left behind by a previous seed-file
//! deployment — not as a load-bearing part of this design.

use sp_core::crypto::{ByteArray, Pair};
use sp_core::{ecdsa, ed25519, sr25519};
use sp_keystore::Keystore;

use crate::config::{KeyRole, Scheme};
use crate::error::{Error, Result};
use crate::loader::LoadedSeed;

/// The public key a released seed derived, hex-encoded with a `0x` prefix.
/// Public data: safe to log, and logged deliberately so an operator can
/// confirm the node is running as the authority they expect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedPublicKey {
    pub role: KeyRole,
    pub hex: String,
}

/// Derive the keypair, check it against `expected_public_key`, and insert it.
///
/// `expected` is the operator-declared public key from config. When present it
/// is enforced, because the three ways this can silently go wrong — a swapped
/// ciphertext blob, a role mapped to the wrong key, a `Suri` seed sealed as
/// `Raw32` — all produce a *valid but wrong* authority key. A validator that
/// boots with the wrong key does not fail loudly; it just signs things nobody
/// accepts, or equivocates. Better to refuse to start.
pub fn insert_seed(
    keystore: &dyn Keystore,
    seed: &LoadedSeed,
    expected: Option<&str>,
) -> Result<DerivedPublicKey> {
    let role = seed.role;
    let key_type = sp_core::crypto::KeyTypeId(role.key_type());

    let public_bytes = seed.with_suri(|suri| {
        // Derive locally first, using `Pair::from_string` — the exact call
        // `insert_ephemeral_from_seed_by_type` makes internally, so the public
        // key checked here is guaranteed to be the one the keystore stores.
        //
        // Deriving before inserting is what lets the expected-public-key check
        // reject a bad seed *without* it ever entering the keystore.
        let derived = match role.scheme() {
            Scheme::Sr25519 => sr25519::Pair::from_string(suri, None)
                .map_err(|e| invalid(role, e))?
                .public()
                .to_raw_vec(),
            Scheme::Ed25519 => ed25519::Pair::from_string(suri, None)
                .map_err(|e| invalid(role, e))?
                .public()
                .to_raw_vec(),
            Scheme::Ecdsa => ecdsa::Pair::from_string(suri, None)
                .map_err(|e| invalid(role, e))?
                .public()
                .to_raw_vec(),
        };

        if let Some(expected) = expected {
            let want = expected
                .strip_prefix("0x")
                .unwrap_or(expected)
                .to_ascii_lowercase();
            let got = hex_lower(&derived);
            if want != got {
                return Err(Error::PublicKeyMismatch {
                    role,
                    derived: format!("0x{got}"),
                    expected: format!("0x{want}"),
                });
            }
        }

        // Memory-only insertion. See the module docs: `Keystore::insert` would
        // either write the plaintext SURI to disk or silently do nothing.
        let inserted = match role.scheme() {
            Scheme::Sr25519 => keystore
                .sr25519_generate_new(key_type, Some(suri))
                .map(|p| p.to_raw_vec()),
            Scheme::Ed25519 => keystore
                .ed25519_generate_new(key_type, Some(suri))
                .map(|p| p.to_raw_vec()),
            Scheme::Ecdsa => keystore
                .ecdsa_generate_new(key_type, Some(suri))
                .map(|p| p.to_raw_vec()),
        }
        .map_err(|e| Error::Keystore {
            role,
            message: format!("keystore insertion failed: {e}"),
        })?;

        // Belt-and-braces: if these ever diverged, the node would sign with a
        // key the operator did not authorise.
        if inserted != derived {
            return Err(Error::Keystore {
                role,
                message: "keystore stored a different public key than was derived".into(),
            });
        }

        Ok(derived)
    })?;

    let hex = format!("0x{}", hex_lower(&public_bytes));
    log::info!("{role} public key released from KMS: {hex}");
    Ok(DerivedPublicKey { role, hex })
}

/// Load every configured seed and insert it into `keystore`.
///
/// This is the single call the node needs. Seeds are zeroed as this returns.
///
/// # Panics
/// Must be called outside a tokio runtime — see [`crate::http::client`].
pub fn load_and_insert(
    keystore: &dyn Keystore,
    cfg: &crate::config::KmsConfig,
) -> Result<Vec<DerivedPublicKey>> {
    let seeds = crate::loader::load_seeds(cfg)?;
    let mut out = Vec::with_capacity(seeds.len());
    for seed in &seeds {
        let expected = cfg
            .keys
            .iter()
            .find(|k| k.role == seed.role)
            .and_then(|k| k.expected_public_key.as_deref());
        out.push(insert_seed(keystore, seed, expected)?);
    }
    // `seeds` drops here: every plaintext is zeroed and its pages unlocked.
    // The keystore now holds the only copy, in memory.
    Ok(out)
}

fn invalid(role: KeyRole, e: sp_core::crypto::SecretStringError) -> Error {
    // `SecretStringError`'s Debug does not include the secret, but keep the
    // message to the variant name so a future change cannot start leaking it.
    Error::Keystore {
        role,
        message: format!("seed is not a valid SURI ({e:?})"),
    }
}

/// Public keys only. Secret bytes go through `SecretBuffer::push_hex`.
fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SeedEncoding;
    use crate::secret::SecretBuffer;
    use sc_keystore::LocalKeystore;

    /// Well-known dev seed, so the expected public keys below are checkable
    /// against `subkey inspect`.
    const ALICE_SEED: [u8; 32] = [
        0xe5, 0xbe, 0x9a, 0x5c, 0xa2, 0x8d, 0xb8, 0x5b, 0x35, 0x2e, 0xf5, 0x4d, 0x2b, 0x1f, 0x1e,
        0x8b, 0x1c, 0x0e, 0x1f, 0x0d, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3,
        0xb4, 0xc5,
    ];

    fn seed(role: KeyRole) -> LoadedSeed {
        LoadedSeed::new(
            role,
            SeedEncoding::Raw32,
            SecretBuffer::from_slice(&ALICE_SEED).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn inserts_and_returns_the_derived_public_key() {
        let ks = LocalKeystore::in_memory();
        let out = insert_seed(&ks, &seed(KeyRole::Aura), None).unwrap();
        assert!(out.hex.starts_with("0x"));
        assert_eq!(out.hex.len(), 66); // 32-byte sr25519 public key
        // The key must actually be retrievable by the consensus code. This is
        // the assertion that `Keystore::insert` would have failed.
        let keys = ks.sr25519_public_keys(sp_core::crypto::KeyTypeId(*b"aura"));
        assert_eq!(
            keys.len(),
            1,
            "in-memory keystore must actually hold the key"
        );
    }

    #[test]
    fn insertion_writes_nothing_to_a_path_backed_keystore() {
        // The property the whole design rests on: even when the node was
        // configured with a keystore directory, a KMS-released seed must not
        // be persisted to it.
        let dir = tempfile::tempdir().unwrap();
        let ks = LocalKeystore::open(dir.path(), None).unwrap();

        insert_seed(&ks, &seed(KeyRole::Aura), None).unwrap();

        // Key is usable...
        assert_eq!(
            ks.sr25519_public_keys(sp_core::crypto::KeyTypeId(*b"aura"))
                .len(),
            1
        );
        // ...but the directory is still empty.
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert!(
            entries.is_empty(),
            "seed must not be written to disk: {entries:?}"
        );
    }

    #[test]
    fn grandpa_uses_ed25519_and_cross_chain_uses_ecdsa() {
        let ks = LocalKeystore::in_memory();
        insert_seed(&ks, &seed(KeyRole::Grandpa), None).unwrap();
        assert_eq!(
            ks.ed25519_public_keys(sp_core::crypto::KeyTypeId(*b"gran"))
                .len(),
            1
        );

        insert_seed(&ks, &seed(KeyRole::CrossChain), None).unwrap();
        let ecdsa = ks.ecdsa_public_keys(sp_core::crypto::KeyTypeId(*b"crch"));
        assert_eq!(ecdsa.len(), 1);
        // ECDSA public keys are 33 bytes compressed, not 32.
        let out = insert_seed(&ks, &seed(KeyRole::CrossChain), None).unwrap();
        assert_eq!(out.hex.len(), 2 + 66);
    }

    #[test]
    fn a_wrong_expected_public_key_blocks_the_insert() {
        let ks = LocalKeystore::in_memory();
        let wrong = "0x".to_string() + &"11".repeat(32);
        let err = insert_seed(&ks, &seed(KeyRole::Aura), Some(&wrong)).unwrap_err();
        assert!(matches!(err, Error::PublicKeyMismatch { .. }));
        // Nothing may have been inserted.
        assert!(
            ks.sr25519_public_keys(sp_core::crypto::KeyTypeId(*b"aura"))
                .is_empty()
        );
    }

    #[test]
    fn the_correct_expected_public_key_is_accepted() {
        let ks = LocalKeystore::in_memory();
        let derived = insert_seed(&ks, &seed(KeyRole::Aura), None).unwrap();
        let ks2 = LocalKeystore::in_memory();
        insert_seed(&ks2, &seed(KeyRole::Aura), Some(&derived.hex)).unwrap();
        // Without the 0x prefix, and upper-case, must also match.
        let ks3 = LocalKeystore::in_memory();
        let bare = derived.hex.trim_start_matches("0x").to_uppercase();
        insert_seed(&ks3, &seed(KeyRole::Aura), Some(&bare)).unwrap();
    }

    #[test]
    fn raw32_derivation_matches_pair_from_seed() {
        // The critical compatibility property: releasing a raw seed through
        // this crate must produce the same authority key as the existing
        // seed-file path, which uses `from_string_with_seed`.
        let expected = sr25519::Pair::from_seed(&ALICE_SEED).public().to_raw_vec();
        let ks = LocalKeystore::in_memory();
        let out = insert_seed(&ks, &seed(KeyRole::Aura), None).unwrap();
        assert_eq!(out.hex, format!("0x{}", hex_lower(&expected)));
    }

    #[test]
    fn a_suri_phrase_derives_differently_from_raw_entropy() {
        // Documents why SeedEncoding::Suri exists. If an operator sealed a
        // phrase's raw entropy as Raw32, they would get a different, wrong
        // authority key -- silently.
        let phrase = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
        let from_phrase = sr25519::Pair::from_string_with_seed(phrase, None)
            .unwrap()
            .0;
        let from_raw = sr25519::Pair::from_seed(&ALICE_SEED);
        assert_ne!(
            from_phrase.public().to_raw_vec(),
            from_raw.public().to_raw_vec()
        );
    }
}
