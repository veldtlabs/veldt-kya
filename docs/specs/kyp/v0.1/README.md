# KYP v0.1 — Specification

**Status: DRAFT — soliciting comments.** This is an early-stage spec
under active development. The wire format and signing scheme defined
here may change in incompatible ways before v1.0. Implementers are
welcome and feedback is strongly encouraged.

KYP (Know Your Principal) is a wire-format and verification
specification for **authority, delegation, attribution, and verifiable
records** across autonomous systems — humans, AI agents, service
accounts, drones, robots, and other autonomous actors.

## Scope of v0.1

This v0.1 release defines the three sections that are critical for
**cross-implementation interoperability**:

| Section | What it defines |
|---|---|
| [`03-evidence-record.md`](./03-evidence-record.md) | The JSON shape that goes on the wire — fields, kinds, semantics |
| [`04-canonicalization.md`](./04-canonicalization.md) | Deterministic serialization rules so two implementations produce byte-identical input to the signer |
| [`05-signing.md`](./05-signing.md) | HMAC scheme, payload-hash and chain-link computation |

The remaining sections (terminology, principal model, edge model, full
verification algorithm, conformance criteria) will land incrementally.
They are **documentation around** the wire format — they don't change
what bytes implementations emit.

## Reference implementation

`veldt-kya` on PyPI — specifically `kya/evidence.py` in the
[veldt-kya repo](https://github.com/veldtlabs/veldt-kya). The reference
implementation is normative for v0.1: where this spec is ambiguous, the
reference implementation's behavior is the authority. v0.2 will invert
that — the spec will be normative and the reference implementation
must conform.

## Test vectors

Each implementation MUST pass the test vectors in
[`test-vectors/`](./test-vectors/). The reference implementation's
output is used to generate these vectors; future implementations in
Go / Rust / Java / TypeScript / etc. validate against the same
vectors.

## Versioning

The spec follows SemVer. See [`VERSIONING.md`](./VERSIONING.md).

- **0.x** — the wire format and signing scheme may change without
  notice. Implementations should pin to a specific minor version.
- **1.0** — wire format frozen. Breaking changes require a major bump.

## Conformance

A "KYP-conformant" implementation MUST:

1. Emit evidence records matching [`03-evidence-record.md`](./03-evidence-record.md)
2. Canonicalize payloads per [`04-canonicalization.md`](./04-canonicalization.md),
   producing byte-identical output to the test vectors
3. Sign chains per [`05-signing.md`](./05-signing.md), producing
   byte-identical `signed_hash` values to the test vectors
4. Verify any KYP-conformant chain end-to-end (algorithm spec lands in
   `07-verification.md`)

Full conformance criteria and a standalone test suite (`kyp-conformance`)
land in v0.2.
