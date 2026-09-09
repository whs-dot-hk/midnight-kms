//! Cross-language contract test for the AAD.
//!
//! `tools/seal-seed.sh` builds the AAD in bash and Cloud KMS authenticates it;
//! `src/config.rs` rebuilds it in Rust at decrypt time. KMS compares the two
//! byte-for-byte and returns only "the AAD provided does not match" if they
//! differ -- at validator startup, long after sealing, with no clue as to
//! which side is wrong.
//!
//! So the exact bytes are pinned here as golden values. If a change to
//! `config::aad` breaks this test, it will also make every already-sealed blob
//! in production undecryptable, and the fix is a new AAD *version*, not an
//! updated expectation.
//!
//! Regenerate a golden value with:
//! ```sh
//! printf 'midnight-kms/v1\0chain=%s\0role=%s\0enc=%s' mainnet aura raw32 | base64 -w0
//! ```

use base64::Engine;
use midnight_kms::config::{KeyRole, SeedEncoding, aad};

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[test]
fn aad_bytes_match_the_sealing_script() {
    // Produced by tools/seal-seed.sh for
    // --chain-id midnight-mainnet --role aura --encoding raw32
    let golden = "bWlkbmlnaHQta21zL3YxAGNoYWluPW1pZG5pZ2h0LW1haW5uZXQAcm9sZT1hdXJhAGVuYz1yYXczMg==";
    let computed = b64(&aad("midnight-mainnet", KeyRole::Aura, SeedEncoding::Raw32));
    assert_eq!(
        computed, golden,
        "AAD drifted from tools/seal-seed.sh. Every sealed blob in production \
         is now undecryptable. Version the AAD instead of changing v1."
    );
}

#[test]
fn aad_has_no_trailing_newline_or_padding() {
    // `printf` in the shell script emits no trailing newline. A stray one here
    // would be invisible in a diff and fatal at startup.
    let bytes = aad("mainnet", KeyRole::Grandpa, SeedEncoding::Suri);
    assert!(!bytes.ends_with(b"\n"));
    assert!(!bytes.ends_with(&[0]));
    assert!(bytes.starts_with(b"midnight-kms/v1\0"));
}

#[test]
fn every_role_and_encoding_combination_is_unique() {
    let roles = [
        KeyRole::Aura,
        KeyRole::Babe,
        KeyRole::Grandpa,
        KeyRole::CrossChain,
    ];
    let encodings = [SeedEncoding::Raw32, SeedEncoding::Suri];

    let mut seen: Vec<Vec<u8>> = Vec::new();
    for chain in ["mainnet", "testnet-02"] {
        for role in roles {
            for encoding in encodings {
                let a = aad(chain, role, encoding);
                assert!(
                    !seen.contains(&a),
                    "AAD collision for {chain}/{role}/{encoding:?}"
                );
                seen.push(a);
            }
        }
    }
    assert_eq!(seen.len(), 2 * 4 * 2);
}

#[test]
fn role_names_in_the_aad_are_the_frozen_wire_format() {
    // These strings are baked into every sealed blob. The shell script
    // validates the same four names.
    assert_eq!(KeyRole::Aura.as_str(), "aura");
    assert_eq!(KeyRole::Babe.as_str(), "babe");
    assert_eq!(KeyRole::Grandpa.as_str(), "grandpa");
    assert_eq!(KeyRole::CrossChain.as_str(), "cross_chain");
    assert_eq!(SeedEncoding::Raw32.as_str(), "raw32");
    assert_eq!(SeedEncoding::Suri.as_str(), "suri");
}
