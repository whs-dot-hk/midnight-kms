# Integrating into midnight-node

Verified against `midnightntwrk/midnight-node` @ `main` (partner-chains 1.8.1,
polkadot-stable2606) and the file/line references below are from that tree.

## Dependency versions

The standalone crate pins crates.io versions so it can be built and tested on
its own:

| crate       | standalone (crates.io) | inside midnight-node            |
|-------------|------------------------|---------------------------------|
| sp-core     | `43`                   | `{ workspace = true }`          |
| sp-keystore | `0.49`                 | `{ workspace = true }`          |
| sc-keystore | `42` (dev)             | `{ workspace = true }` (dev)    |

When vendored, switch these to `workspace = true` so they resolve to the
workspace's `polkadot-stable2606` git tag. The `Keystore` trait signatures were
checked against that tag directly — `fn insert(&self, KeyTypeId, &str, &[u8])
-> Result<(), ()>` and `fn sr25519_generate_new(&self, KeyTypeId,
Option<&str>)` are unchanged between it and the published crates.

Everything else the crate needs is already a workspace dependency:
`zeroize` (with `derive`), `reqwest` (`rustls-tls` + `blocking`), `thiserror`,
`serde`, `serde_json`, `log`, `libc`. Only `base64` needs adding.

`[profile.release] panic = "unwind"` in the workspace root is load-bearing:
zeroization runs in `Drop`, so it happens on an unwinding panic. If the profile
were ever switched to `panic = "abort"`, destructors would be skipped and
secrets would survive a panic in freed memory.

## 1. Workspace registration

```toml
# Cargo.toml
 members = [
     "ledger",
+    "node/kms",
     "node",
```

```toml
# Cargo.toml  [workspace.dependencies]
+base64 = { version = "0.22", default-features = false, features = ["alloc"] }
+midnight-kms = { path = "node/kms", features = ["substrate"] }
```

## 2. Config surface

`node/src/cfg/midnight_cfg/mod.rs` — alongside the existing `*_seed_file`
options:

```rust
    /// Path to file containing a secret string to use as the CROSS_CHAIN seed
    pub cross_chain_seed_file: Option<String>,

+   /// Release validator keys from Cloud KMS, gated on a GCP Confidential
+   /// Space attestation, instead of reading plaintext seed files.
+   ///
+   /// Mutually exclusive with the `*_seed_file` options above: configuring
+   /// both is rejected at startup rather than silently preferring one.
+   pub kms_config_file: Option<String>,
```

The KMS config is a separate JSON file rather than a dozen flattened options
because it is a nested per-role structure, and because `MidnightCfg` derives
`Debug` — a struct that big is easy to accidentally log. Nothing in
`KmsConfig` is secret, so the file needs no special permissions.

## 3. `node/src/command.rs`

Replace the four seed-file blocks (currently lines 226–275). Note the existing
code creates a `LocalKeystore::open(path, password)` *purely* to insert seeds
into the same directory the service will later open — the plaintext seed
reaches the node by being written to disk. That is the mechanism being
replaced.

```rust
 	let keystore: KeystorePtr = {
 		let res = run_cmd.keystore_params().unwrap().keystore_config(&config_dir)?;
 		if let KeystoreConfig::Path { path, password } = res {
 			LocalKeystore::open(path, password)?.into()
 		} else {
 			panic!("InMemory Keystore not supported")
 		}
 	};

+	// Refuse the ambiguous configuration outright: silently preferring one
+	// source would mean an operator who thinks they migrated to KMS could
+	// still be running from a plaintext seed file.
+	let seed_files_configured = cfg.midnight_cfg.aura_seed_file.is_some()
+		|| cfg.midnight_cfg.babe_seed_file.is_some()
+		|| cfg.midnight_cfg.grandpa_seed_file.is_some()
+		|| cfg.midnight_cfg.cross_chain_seed_file.is_some();
+	if cfg.midnight_cfg.kms_config_file.is_some() && seed_files_configured {
+		return Err(sc_cli::Error::Input(
+			"KMS_CONFIG_FILE cannot be combined with the *_SEED_FILE options".into(),
+		));
+	}
+
+	if let Some(path) = &cfg.midnight_cfg.kms_config_file {
+		// Nothing in this file is secret; it is public config.
+		let kms_cfg: midnight_kms::KmsConfig = serde_json::from_str(
+			&std::fs::read_to_string(path).map_err(|e| {
+				sc_cli::Error::Input(format!("reading KMS config at {path}: {e}"))
+			})?,
+		)
+		.map_err(|e| sc_cli::Error::Input(format!("parsing KMS config at {path}: {e}")))?;
+
+		// Blocking HTTP, so this must stay outside the tokio runtime — which
+		// it is: `runner.run_node_until_exit` is not entered until below.
+		let released = midnight_kms::keystore::load_and_insert(&*keystore, &kms_cfg)
+			.map_err(|e| sc_cli::Error::Application(Box::new(e)))?;
+		for key in released {
+			log::info!("{} pubkey: {}", key.role, key.hex);
+		}
+	}
+
 	if let Some(seed_file) = &cfg.midnight_cfg.aura_seed_file {
 		let seed = std::fs::read_to_string(seed_file).map_err(|e| {
 		...
```

### Why this can insert into the *path-backed* keystore safely

`load_and_insert` calls `Keystore::{sr25519,ed25519,ecdsa}_generate_new(
key_type, Some(suri))`. Despite the name, `Some` means "derive from this SURI",
and it routes to `insert_ephemeral_from_seed_by_type` →
`insert_ephemeral_pair`, documented in
`substrate/client/keystore/src/local.rs` as *"Does not place it into the file
system store."*

It does **not** call `Keystore::insert`, which would be wrong twice over:

* on a path-backed keystore it writes the SURI to a file (this is exactly how
  seeds currently reach the disk), and
* on an in-memory keystore it is a **silent no-op** — `path: None` means the
  `if let` never fires, nothing is added to the `additional` map, `Ok(())` is
  returned, and the node starts as a non-authority with no error.

Because the released seed stays in the keystore's in-memory map either way, no
change to `KeystoreConfig` is *required*. Setting `KeystoreConfig::InMemory`
anyway is still recommended, so that a stale plaintext seed file left behind by
a previous seed-file deployment cannot be picked up by `raw_public_keys`, which
merges the in-memory map with the contents of the keystore directory.

## 4. Wiping the old plaintext seeds

Migrating does not remove what is already on disk. Every host that previously
ran with `*_SEED_FILE` has the seed in **two** places:

1. the seed file itself, and
2. `<base-path>/chains/<chain>/keystore/<hex>` — written by
   `Keystore::insert` → `write_to_file`, mode `0600`, JSON-encoded SURI.

Both must be shredded, and any disk snapshot or backup taken while they existed
should be treated as containing the validator keys. In practice a migration to
attestation-gated release is only meaningfully complete if the authority keys
are **rotated** afterwards — otherwise the pre-migration copies remain valid
signing keys forever.

## 5. Deployment

The node must run as a Confidential Space workload:

```hcl
confidential_instance_config {
  enable_confidential_compute = true   # currently false in
                                       # midnight-iac/gcp/mainnet/europe-west4/main.tf
  confidential_instance_type  = "SEV_SNP"
}

shielded_instance_config {
  enable_secure_boot          = true   # required by the USES_SECUREBOOT
  enable_vtpm                 = true   # attribute condition in kms_tee.tf
  enable_integrity_monitoring = true
}

scheduling {
  on_host_maintenance = "TERMINATE"    # SEV-SNP cannot live-migrate; the
}                                      # current config says MIGRATE
```

Two existing settings conflict with Confidential Space and must change:
`enable_confidential_compute = false`, and `on_host_maintenance = "MIGRATE"`
(a Confidential VM cannot be live-migrated, so instance creation fails).

Boot the **STABLE, secure-boot, non-debug** Confidential Space image. The debug
image permits an interactive shell into the VM, from which the seeds could be
read out of the node's memory; `kms_tee.tf` refuses to release keys to it, and
that check is the reason the debug image is not a foot-gun here.
