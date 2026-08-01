# KYP — Know Your Principal

A wire-format and verification specification for **authority,
delegation, attribution, and verifiable records** across autonomous
systems — humans, AI agents, service accounts, drones, robots, and
other autonomous actors.

**KYP is a specification.** It defines the JSON shape, canonicalization
algorithm, HMAC chain scheme, and verification semantics that any
implementation must follow to interoperate. The reference
implementation ships in the `kya` package, but KYP is intentionally
language-agnostic — implementations in Go, Rust, Java, TypeScript, or
any other language are explicitly welcomed.

> **Status: DRAFT.** v0.x may change incompatibly. The wire format
> stabilizes at v1.0. Implementers should pin to a specific minor
> version (e.g. `v0.1`) and refer to that version's test vectors as
> the authoritative compatibility check.

---

## Why a spec, not just a library

When evidence about *who acted under whose authority* matters —
audits, incident reconstruction, regulatory disclosure, litigation —
the value isn't in any single vendor's code. It's in **multiple
independent implementations producing byte-identical, mutually
verifiable records**.

A `pip install veldt-kya` is the easy path. A KYP spec is what lets a
second vendor emit interoperable evidence without taking a dependency
on the Python implementation, and what lets a regulator or auditor
verify a chain without trusting any single vendor.

The four questions KYP answers:

| Question | What in the spec |
|---|---|
| **Who acted?** | Principal identity + 14 default kinds + extension model |
| **Under what authority?** | Scopes, delegation graph, edge model |
| **Who is accountable?** | Delegation lineage, composed principals |
| **Can you prove it?** | HMAC evidence chain, canonical hashing, verification algorithm |

---

## Published versions

| Version | Status | Sections shipped | Reference impl |
|---|---|---|---|
| [v0.1](./v0.1/) | DRAFT | Evidence record, canonicalization, signing | `veldt-kya >= 0.2.0` |

Each version directory carries:

- **Normative spec docs** — `03-evidence-record.md`,
  `04-canonicalization.md`, `05-signing.md` (more sections land
  incrementally in v0.2)
- **JSON Schema** — machine-validatable record schemas in `schemas/`
- **Test vectors** — `test-vectors/canonicalization/`,
  `test-vectors/signing/`, `test-vectors/chain/`. These are the
  authoritative conformance checks: any implementation must produce
  byte-identical canonical bytes and signature values for every
  vector.
- **`VERSIONING.md`** — semver policy for the spec itself

---

## How to implement KYP (any language)

1. Read the spec docs in the version directory you target.
2. Implement canonicalization to match the test vectors in
   `test-vectors/canonicalization/`.
3. Implement HMAC chain signing to match
   `test-vectors/signing/` and `test-vectors/chain/`.
4. Use the JSON Schema in `schemas/` to validate any record on the
   wire.
5. Optional: implement the verification algorithm so your chains can
   be verified by third parties without your code.

The Python reference implementation is in
[`kya/evidence.py`](../../../kya/evidence.py) — specifically
`_canonicalize`, `_canonical_default`, `_payload_hash`, `_hmac_sign`,
and `verify_chain`. Where the spec is ambiguous in v0.1, the reference
implementation's behavior is normative (this inverts at v1.0).

---

## Conformance

A KYP-conformant implementation **MUST**:

1. Emit evidence records matching the version's
   `03-evidence-record.md` schema
2. Canonicalize payloads per `04-canonicalization.md`, producing
   byte-identical output to every test vector
3. Sign chains per `05-signing.md`, producing byte-identical
   `signed_hash` values to every test vector
4. Verify any KYP-conformant chain end-to-end (algorithm landing in
   `07-verification.md`)

A standalone `kyp-conformance` test-suite package lands in v0.2 so
any implementation in any language can self-certify.

---

## Reference implementation

`veldt-kya` on PyPI: <https://pypi.org/project/veldt-kya/>

Source: <https://github.com/veldtlabs/veldt-kya>

The spec is reverse-documented from the shipping reference
implementation and mechanically bound to it via the pytest harness
at [`tests/test_kyp_spec_v0_1_vectors.py`](../../../tests/test_kyp_spec_v0_1_vectors.py).
Every commit re-runs the vectors; CI fails on any silent drift
between spec text and reference behavior.

---

## Contributing

The spec is under active development. Feedback, second
implementations, and edge-case vectors are all welcome.

- **Issues**: <https://github.com/veldtlabs/veldt-kya/issues>
- **Discussions**: open an issue tagged `spec` for proposals
- **Test vectors**: PRs adding new vectors are accepted as long as
  the reference implementation passes them; if it doesn't, the
  reference behavior changes alongside the spec text

---

## License

Apache License 2.0 — same as the reference implementation. The spec
text and test vectors are explicitly intended to be implemented by
anyone, in any language, for any purpose (commercial or otherwise).
