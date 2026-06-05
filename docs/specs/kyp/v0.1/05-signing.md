# KYP v0.1 — Signing & Chain Integrity

A KYP chain is the sequence of evidence records sharing the same
`(tenant_id, invocation_id)`, in monotonic insertion order. Each
record carries an HMAC over its `payload_hash` and the previous
record's `signed_hash`, so:

- Modifying any record's payload changes its `payload_hash`, which
  changes its `signed_hash`, which propagates a mismatch into every
  later record in the chain.
- Deleting a non-tail record breaks the `prev_hash` link of the next
  surviving record.
- Inserting a forged record requires the signing key.

## Algorithm

### Payload hash

```
payload_hash = sha256_hex( canonicalize(payload) )
```

`canonicalize` is the algorithm in
[`04-canonicalization.md`](./04-canonicalization.md). The result is
the lowercase hex encoding of the 32-byte SHA-256 digest (64 hex
characters).

### Signed hash

```
prev_hash_str = "" if this is the first record in the chain
                else the prev record's signed_hash (64-char hex)

msg_bytes     = utf8( prev_hash_str || "|" || payload_hash )

signed_hash   = hmac_sha256_hex( signing_key, msg_bytes )
```

Notes:

- The separator is a single literal ASCII pipe character (`0x7C`).
- `signed_hash` is the lowercase hex encoding of the 32-byte
  HMAC-SHA256 digest (64 hex characters).
- For the first record in a chain, the message is `"|" + payload_hash`
  — note the leading pipe is still present.
- `signing_key` is the raw key bytes returned by the implementation's
  key provider (see [Key management](#key-management)). The reference
  implementation requires keys of at least 16 bytes; production
  deployments SHOULD use 32 bytes.

### Chain verification (informative)

The full verification algorithm is normative in
[`07-verification.md`](./07-verification.md). The pseudocode below
matches the reference implementation
([`kya/evidence.py:verify_chain`](https://github.com/veldtlabs/veldt-kya/blob/main/kya/evidence.py)):

```
expected_prev = ""
for row in chain_rows_in_id_order:
    if sha256_hex(canonicalize(row.payload)) != row.payload_hash:
        return BROKEN("payload modified")
    if (row.prev_hash or "") != expected_prev:
        return BROKEN("prev_hash break — insert/delete/modify")
    if hmac_sha256_hex(key, expected_prev || "|" || row.payload_hash) != row.signed_hash:
        return BROKEN("signed_hash mismatch — forged or key changed")
    expected_prev = row.signed_hash
return VALID
```

**Security note — HMAC input MUST be the verifier-computed
`expected_prev`, not the stored `row.prev_hash`.** A forger with
write access could otherwise flip both `prev_hash` and `signed_hash`
in lockstep and pass HMAC verification while still breaking the
chain. By recomputing `expected_prev` from the previous row's
`signed_hash` and comparing the result to `row.prev_hash` *and*
using `expected_prev` in the HMAC input, the verifier closes that
gap.

## Key management

`signing_key_id` is required on every record so verifiers can look
up the correct key during rotation. Key resolution is implementation-
defined; the reference implementation uses (in order):

1. `KYA_EVIDENCE_KEY_PROVIDER` env var pointing at a pluggable
   `module:function` returning `(key_bytes, key_id)`. Used for AWS
   KMS / GCP KMS / HashiCorp Vault integration.
2. `KYA_EVIDENCE_SIGNING_KEY` env var with base64-encoded key bytes
   (≥ 16 bytes). `signing_key_id` is taken from
   `KYA_EVIDENCE_SIGNING_KEY_ID` or defaults to `env-v1`.
3. A process-local random 32-byte dev key (with a warning logged).
   `signing_key_id` is `dev-local`.

Conformant implementations MUST support at least one mechanism
equivalent to (1) or (2) for production use; the dev fallback is
optional but RECOMMENDED for local testing ergonomics.

## Constraints

- `signing_key` bytes MUST NOT appear on the wire — only
  `signing_key_id` is stored.
- Implementations MUST reject keys shorter than 16 bytes.
- Implementations MUST use HMAC-SHA256. v0.1 does NOT support
  HMAC-SHA512, Ed25519, or other signature schemes. (Pluggable
  signature schemes are scheduled for v0.3.)
- A KYP chain MUST NOT mix records signed with different keys
  silently. When `signing_key_id` changes within a chain, verifiers
  MUST either:
  - Look up the correct historical key and verify with it, OR
  - Treat the change as a `signed_hash mismatch — signing key
    changed` break and report it explicitly.

  The reference implementation currently uses the second behavior
  (v1 verifier always uses the current key); historical key support
  is scheduled for v0.3.

## Test vectors

Reference test vectors live at
[`test-vectors/signing/`](./test-vectors/signing/) and
[`test-vectors/chain/`](./test-vectors/chain/).

- `signing/` — single-record vectors: `(prev_hash, payload_hash, key)` → `signed_hash`.
- `chain/` — multi-record vectors: a full N-row chain with expected
  verification result.

Conformant implementations MUST produce byte-identical `signed_hash`
values for every signing vector AND MUST reach the same
verification verdict for every chain vector.
