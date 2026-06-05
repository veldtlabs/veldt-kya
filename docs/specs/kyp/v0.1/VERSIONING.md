# KYP Spec — Versioning Policy

The KYP spec follows [SemVer](https://semver.org/spec/v2.0.0.html).

| Version range | Stability promise |
|---|---|
| `0.1.x` | Wire format and signing scheme may change. Implementations should pin to a specific minor version. Use for evaluation, internal pilots, and review. |
| `0.x` | Each minor bump may include breaking changes to the wire format, canonicalization, signing, or evidence-kind enum. Test vectors regenerate per minor. |
| `1.0` and later | Wire format is frozen. Breaking changes require a major bump. Conformance test suite (`kyp-conformance`) freezes alongside. |

## What counts as a breaking change

- Renaming or removing any REQUIRED field on the evidence record.
- Changing the semantics of `prev_hash` linking or the HMAC message format.
- Renaming or removing any value in the `evidence_kind` enum.
- Changing the canonical-form algorithm in a way that yields different bytes for any pre-existing test vector input.
- Changing the signing scheme (algorithm, key derivation, or message bytes).

## What does not count as a breaking change

- **Adding** new OPTIONAL fields on the evidence record.
- **Adding** new values to the `evidence_kind` enum.
- Adding new evidence subkinds via convention in the `payload` object.
- Adding new test vectors that all current implementations already pass.
- Clarifying language in the spec text where it does not change observable behavior.

## Spec version vs reference implementation version

The KYP spec version is independent of the `veldt-kya` package
version. v0.1 of the spec is shipped alongside `veldt-kya 0.2.0` but
the two will not march in lockstep. Each spec version's reference
implementation is pinned by tag (e.g., `kyp-v0.1-ref` will point at
the `veldt-kya` commit that defines v0.1's normative behavior).

## Compatibility window

While in `0.x`, implementations SHOULD declare the spec version they
target via the `signing_key_id` namespacing convention or via an
out-of-band agreement. Cross-version chain verification is not
defined in v0.1.
