#!/usr/bin/env bash
# Seal a validator seed into a KMS ciphertext blob that only an attested
# Confidential Space workload can decrypt.
#
# Run this ONCE per key, on a trusted machine, as the sealer service account.
# The plaintext seed must never be written to disk in the process -- this
# script therefore reads it from stdin and pipes it straight to the API.
#
#   ./seal-seed.sh --role aura --chain-id midnight-mainnet \
#       --kms-key projects/P/locations/L/keyRings/R/cryptoKeys/K \
#       --encoding raw32 < seed.bin > aura.seed.enc
#
# The output blob is NOT secret -- it is inert without an attested decrypt --
# so it can be baked into an image, a ConfigMap, or instance metadata.

set -euo pipefail

ROLE="" CHAIN_ID="" KMS_KEY="" ENCODING="raw32"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --role)     ROLE="$2"; shift 2 ;;
    --chain-id) CHAIN_ID="$2"; shift 2 ;;
    --kms-key)  KMS_KEY="$2"; shift 2 ;;
    --encoding) ENCODING="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

for required in ROLE CHAIN_ID KMS_KEY; do
  if [[ -z "${!required}" ]]; then
    echo "--${required,,} is required" >&2; exit 2
  fi
done

case "$ROLE" in
  aura|babe|grandpa|cross_chain) ;;
  *) echo "role must be one of aura babe grandpa cross_chain" >&2; exit 2 ;;
esac

case "$ENCODING" in
  raw32|suri) ;;
  *) echo "encoding must be raw32 or suri" >&2; exit 2 ;;
esac

if [[ ! "$CHAIN_ID" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "chain-id must match [A-Za-z0-9._-]+ (it is part of the AAD)" >&2; exit 2
fi

# MUST byte-for-byte match config::aad() in src/config.rs. A mismatch here does
# not fail at sealing time -- it fails much later, at node startup, as an
# opaque "Decryption failed: the AAD provided does not match".
AAD=$(printf 'midnight-kms/v1\0chain=%s\0role=%s\0enc=%s' "$CHAIN_ID" "$ROLE" "$ENCODING" | base64 -w0)

TMP_UMASK=$(umask); umask 0077

# Read the seed from stdin. Never a file argument: a path invites leaving the
# plaintext seed lying around, and shell history would record it.
SEED_B64=$(base64 -w0)

if [[ -z "$SEED_B64" ]]; then
  echo "no seed on stdin" >&2; exit 2
fi

if [[ "$ENCODING" == "raw32" ]]; then
  SEED_LEN=$(printf '%s' "$SEED_B64" | base64 -d | wc -c)
  if [[ "$SEED_LEN" -ne 32 ]]; then
    echo "raw32 requires exactly 32 bytes on stdin, got ${SEED_LEN}" >&2
    echo "hint: a hex seed file needs 'xxd -r -p' first; a BIP39 phrase needs --encoding suri" >&2
    exit 2
  fi
fi

RESPONSE=$(
  curl -sS --fail-with-body \
    -X POST \
    -H @<(printf 'Authorization: Bearer %s' "$(gcloud auth print-access-token)") \
    -H "Content-Type: application/json" \
    --data @<(printf '{"plaintext":"%s","additionalAuthenticatedData":"%s"}' "$SEED_B64" "$AAD") \
    "https://cloudkms.googleapis.com/v1/${KMS_KEY}:encrypt"
)

unset SEED_B64
umask "$TMP_UMASK"

# Emit only the base64 ciphertext, so the output can be redirected straight
# into the file the node reads.
printf '%s' "$RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["ciphertext"])'

cat >&2 <<MSG

Sealed ${ROLE} seed for chain ${CHAIN_ID} (encoding=${ENCODING}).

Next: record the corresponding PUBLIC key as expected_public_key in the node's
KMS config. Without it, a swapped blob or a wrong role mapping produces a
valid-but-wrong authority key and the node starts happily while signing
nothing anyone accepts.

  midnight-node key inspect --scheme <sr25519|ed25519|ecdsa> <seed>
MSG
