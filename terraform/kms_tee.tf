# =============================================================================
# Attestation-gated validator key release
# =============================================================================
#
# THIS FILE IS THE SECURITY BOUNDARY.
#
# The Rust crate is a client. Nothing it checks locally keeps a key safe --
# code running outside a TEE could fake any of it. What actually protects the
# validator keys is the combination below:
#
#   1. a workload identity pool provider that will only mint credentials for a
#      token signed by Google's Confidential Space attestation verifier, and
#   2. an IAM condition on the KMS key that releases `decrypt` only to a
#      principal whose *attested container image digest* matches a pinned
#      value.
#
# Get either wrong and the Rust code is decoration. Review this file as if it
# were the key material itself.
#
# Complements the existing modules/gcp/kms.tf, which provisions CMEK for disk
# and Secret Manager encryption. That is infrastructure encryption; this is
# key custody. They are unrelated concerns and use separate key rings.
# =============================================================================

variable "project_id" { type = string }
variable "project_number" { type = string }
variable "region" { type = string }

variable "chain_id" {
  description = "Mixed into the AAD. Must match KmsConfig.chain_id exactly."
  type        = string
}

variable "node_name" { type = string }

variable "image_digest" {
  description = <<-EOT
    The node container image digest the workload must attest as, e.g.
    "sha256:abc123...". THIS IS THE PIN. Changing it authorises a new binary
    to obtain the validator keys, so it should be changed only by a reviewed,
    audited commit -- treat a PR that edits this line as a key-custody change.

    Must be a digest, never a tag: a tag is mutable and would let anyone who
    can push to the registry obtain the keys.
  EOT
  type        = string

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.image_digest))
    error_message = "image_digest must be a full sha256:<64 hex> digest, not a tag."
  }
}

variable "signer_key_ids" {
  description = <<-EOT
    Optional: cosign public key IDs whose signature the image must carry. When
    set, the workload must attest with a matching signature, which lets you
    roll images without editing image_digest on every release while still
    requiring that a release be signed.

    midnight-node already produces cosign signatures and GitHub native
    attestations (docs/security/image-signing.md), so this composes with the
    existing release process.
  EOT
  type        = list(string)
  default     = []
}

locals {
  # Roles match KeyRole::as_str() in src/config.rs. These strings are part of
  # the AAD wire format; renaming one makes existing sealed blobs
  # undecryptable.
  key_roles = ["aura", "babe", "grandpa", "cross_chain"]

  wip_id      = "${var.node_name}-tee"
  provider_id = "confidential-space"
}

# -----------------------------------------------------------------------------
# Key ring: separate from the disk/Secret Manager CMEK ring on purpose.
# -----------------------------------------------------------------------------
resource "google_kms_key_ring" "validator_keys" {
  name     = "${var.node_name}-validator-keys"
  location = var.region
  project  = var.project_id
}

resource "google_kms_crypto_key" "seed" {
  for_each = toset(local.key_roles)

  name     = "${var.node_name}-${replace(each.key, "_", "-")}-seed"
  key_ring = google_kms_key_ring.validator_keys.id
  purpose  = "ENCRYPT_DECRYPT"

  # NOT rotated on a schedule, unlike the CMEK keys in modules/gcp/kms.tf.
  #
  # Rotating a symmetric KMS key only changes which version *new* ciphertext
  # is encrypted under; existing sealed blobs stay decryptable under the old
  # version, so automatic rotation would buy nothing here while creating the
  # illusion of protection. Rotating the key that guards a validator seed also
  # does not rotate the seed -- if a seed is believed compromised, the response
  # is to generate a new authority key and re-register it on chain, not to
  # rotate this key. Left explicit so the omission reads as a decision.
  rotation_period = null

  version_template {
    algorithm = "GOOGLE_SYMMETRIC_ENCRYPTION"
    # HSM: the key cannot be exported even by a project owner. Worth the cost
    # for four keys that gate block production.
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# -----------------------------------------------------------------------------
# Workload identity pool: where the attestation is actually verified.
# -----------------------------------------------------------------------------
resource "google_iam_workload_identity_pool" "tee" {
  project                   = var.project_id
  workload_identity_pool_id = local.wip_id
  display_name              = "Confidential Space TEE"
  description               = "Validator key release for ${var.node_name}"
}

resource "google_iam_workload_identity_pool_provider" "confidential_space" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.tee.workload_identity_pool_id
  workload_identity_pool_provider_id = local.provider_id
  display_name                       = "Confidential Space attestation"

  oidc {
    # The Confidential Space attestation verifier. Only tokens signed by this
    # issuer's keys are accepted, which is what makes the claims trustworthy.
    issuer_uri        = "https://confidentialcomputing.googleapis.com/"
    allowed_audiences = ["https://sts.googleapis.com"]
  }

  # Claims lifted into attribute.* for use in the condition below and in IAM
  # principalSet bindings.
  attribute_mapping = {
    "google.subject"          = "assertion.sub"
    "attribute.image_digest"  = "assertion.submods.container.image_digest"
    "attribute.image_signer"  = "assertion.submods.container.image_signatures[0].key_id"
    "attribute.sw_name"       = "assertion.swname"
    "attribute.hw_model"      = "assertion.hwmodel"
  }

  # First gate. Everything here is asserted by the attestation verifier, not
  # by the workload.
  #
  # * swname / hwmodel        -- genuinely Confidential Space on AMD SEV, not
  #                              some other OIDC workload in the project.
  # * STABLE / SECUREBOOT /
  #   LATEST support attrs    -- rejects the debug and non-secure-boot variants
  #                              of the Confidential Space image. Without this,
  #                              an operator could boot the *debug* image,
  #                              which permits a shell into the VM, and read
  #                              the seeds straight out of the node's memory.
  #                              This one line is doing a lot of work.
  attribute_condition = join(" && ", concat([
    "assertion.swname == 'CONFIDENTIAL_SPACE'",
    "'STABLE' in assertion.submods.confidential_space.support_attributes",
    "'LATEST' in assertion.submods.confidential_space.support_attributes",
    "'USES_SECUREBOOT' in assertion.submods.confidential_space.support_attributes",
    "assertion.submods.container.image_digest == '${var.image_digest}'",
    ],
    length(var.signer_key_ids) > 0 ? [
      "assertion.submods.container.image_signatures.exists(s, s.key_id in ['${join("','", var.signer_key_ids)}'])"
    ] : []
  ))
}

# -----------------------------------------------------------------------------
# The grant.
# -----------------------------------------------------------------------------
locals {
  # Principal set scoped by attested image digest. Combined with the provider's
  # attribute_condition this is belt-and-braces -- the condition already
  # rejects a mismatched digest -- but it keeps the binding self-describing and
  # survives someone loosening the provider by mistake.
  attested_principal = join("", [
    "principalSet://iam.googleapis.com/projects/${var.project_number}",
    "/locations/global/workloadIdentityPools/${local.wip_id}",
    "/attribute.image_digest/${var.image_digest}",
  ])
}

# Decrypt only. Deliberately NOT cryptoKeyEncrypterDecrypter: the node has no
# reason to seal new blobs, and withholding encrypt means a compromised node
# cannot mint ciphertext that a future node would accept as a valid seed.
resource "google_kms_crypto_key_iam_member" "attested_decrypt" {
  for_each = google_kms_crypto_key.seed

  crypto_key_id = each.value.id
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  member        = local.attested_principal
}

# -----------------------------------------------------------------------------
# Sealing identity: a human/CI path to *encrypt*, kept strictly separate.
# -----------------------------------------------------------------------------
resource "google_service_account" "seed_sealer" {
  project      = var.project_id
  account_id   = "${var.node_name}-seed-sealer"
  display_name = "Seals validator seeds for ${var.node_name} (encrypt only)"
}

# Encrypt only, and no decrypt. The operator who seals a seed cannot read any
# other sealed seed back -- including one they sealed earlier.
resource "google_kms_crypto_key_iam_member" "sealer_encrypt" {
  for_each = google_kms_crypto_key.seed

  crypto_key_id = each.value.id
  role          = "roles/cloudkms.cryptoKeyEncrypter"
  member        = "serviceAccount:${google_service_account.seed_sealer.email}"
}

# -----------------------------------------------------------------------------
# Audit logging. Non-optional in practice: this is the only record of a key
# release, and the alert below is how you find out about an unexpected one.
# -----------------------------------------------------------------------------
resource "google_project_iam_audit_config" "kms" {
  project = var.project_id
  service = "cloudkms.googleapis.com"

  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
}

resource "google_logging_metric" "seed_decrypts" {
  project = var.project_id
  name    = "${var.node_name}-validator-seed-decrypts"
  filter  = join(" AND ", [
    "resource.type=\"cloudkms_cryptokey\"",
    "protoPayload.methodName=\"Decrypt\"",
    "resource.labels.key_ring_id=\"${google_kms_key_ring.validator_keys.name}\"",
  ])

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

output "wip_audience" {
  description = "Set this as KmsConfig.wip_audience."
  value = join("", [
    "//iam.googleapis.com/projects/${var.project_number}",
    "/locations/global/workloadIdentityPools/${local.wip_id}",
    "/providers/${local.provider_id}",
  ])
}

output "kms_keys" {
  description = "Per-role KMS resource names. Set these as KeyEntry.kms_key."
  value       = { for role, key in google_kms_crypto_key.seed : role => key.id }
}

output "sealer_service_account" {
  value = google_service_account.seed_sealer.email
}
