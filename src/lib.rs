//! Attestation-gated release of midnight-node validator keys on GCP
//! Confidential Space.
//!
//! # The problem
//!
//! Today `node/src/command.rs` reads each validator seed from a plaintext file
//! (`AURA_SEED_FILE` and friends) and inserts it into a `LocalKeystore` opened
//! on a path — which writes the seed back out under the keystore directory.
//! Anyone who can read the boot disk, a snapshot, or a backup has the
//! validator's signing keys.
//!
//! # The approach
//!
//! Seeds are sealed as Cloud KMS ciphertext, and the KMS key's IAM policy
//! releases `decrypt` **only** to a workload whose Confidential Space
//! attestation matches a pinned container image digest. The sealed blob then
//! needs no protection of its own; it is inert without an attested decrypt.
//!
//! ```text
//!   harden ──▶ attestation token ──▶ STS exchange ──▶ KMS decrypt ──▶ in-memory
//!   (rlimit,    (launcher UDS,        (workload         (+ AAD,        keystore
//!    dumpable)   SEV-SNP measured)     identity pool)    CRC32C)
//! ```
//!
//! # Where the security actually lives
//!
//! **In the KMS IAM condition, not in this crate.** Every local check here is
//! fail-fast diagnostics: code running outside a TEE could return whatever it
//! liked from [`attest`]. What an attacker cannot do is make the workload
//! identity pool accept a token it did not issue, or make KMS release a key to
//! a principal whose attested image digest does not match the condition. The
//! policy in `terraform/kms_tee.tf` is the control; this crate is a client of
//! it.
//!
//! # Residual exposure
//!
//! Once a seed has passed through rustls' TLS record buffers and hyper's
//! internals, copies exist on the ordinary heap that this crate has no handle
//! on. That is unavoidable for any design where a network service returns
//! plaintext, and Cloud KMS is such a service. Zeroization here is therefore
//! defence-in-depth against *post-hoc* disclosure — a heap-overread bug, a
//! stray core file — while the primary protection for key material resident in
//! RAM is SEV-SNP memory encryption plus the absence of swap. See the README.

pub mod attest;
pub mod b64;
pub mod config;
pub mod crc32c;
pub mod error;
pub mod hardening;
pub mod http;
pub mod kms;
pub mod loader;
pub mod secret;
pub mod sts;
pub mod uds;

#[cfg(feature = "substrate")]
pub mod keystore;

pub use config::{AttestConfig, KeyEntry, KeyRole, KmsConfig, Scheme, SeedEncoding};
pub use error::{Error, Result};
pub use loader::{LoadedSeed, load_seeds};
pub use secret::SecretBuffer;
