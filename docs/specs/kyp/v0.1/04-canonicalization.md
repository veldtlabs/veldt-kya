# KYP v0.1 — Canonicalization

To produce byte-identical `payload_hash` and `signed_hash` values
across implementations, payloads MUST be canonicalized to a single
deterministic byte string before hashing.

The algorithm defined here is **JSON-based canonicalization** —
compatible with stock JSON libraries in every mainstream language,
no extra dependencies.

## Algorithm

The canonical form of an evidence payload is the UTF-8 byte
encoding of its JSON serialization with all of the following rules
applied:

1. **Object keys MUST be sorted** in ascending byte-lexicographic
   order (the standard `sort_keys` behavior of stock JSON libraries).
2. **Separators MUST be `","` between elements and `":"` between
   key and value**, with NO whitespace. The serialization MUST emit
   bytes equivalent to the Python expression:

   ```python
   json.dumps(payload, sort_keys=True, separators=(",", ":"),
              default=canonical_default).encode("utf-8")
   ```

3. **Non-JSON-native values MUST be transformed via `canonical_default`** before
   serialization. This rule disambiguates types that JSON would otherwise
   collapse — see [Type-tagging](#type-tagging) below.

4. The canonical form is a **byte string**, not a Unicode string.
   Implementations MUST encode using UTF-8 with no BOM.

5. **Numbers**: implementations MUST emit JSON numbers without
   trailing zeros where the source value is integral (e.g., `42`, not
   `42.0`), and MUST follow stock JSON-library defaults for floats
   (no leading `+`, no exponent unless the source requires it).
   Implementations MUST NOT introduce locale-specific separators.

6. **String escaping**: implementations MUST follow stock JSON
   escaping (`"`, `\`, control characters `0x00`-`0x1F` as `\uXXXX`).
   Non-ASCII characters MUST be emitted as `\uXXXX` escapes (Python
   `ensure_ascii=True` default; the reference implementation relies
   on this default).

7. **NaN / Infinity**: implementations MUST reject `NaN`, `+Infinity`,
   and `-Infinity` payload values (raise / return error). Python's
   stock `json.dumps` emits the non-standard tokens `NaN` / `Infinity`
   by default; conformant implementations MUST pass `allow_nan=False`
   (or its language equivalent) to suppress this.

## Type-tagging

JSON has only 6 primitive types. Other values (timestamps, UUIDs,
binary blobs, sets) would either fail to serialize or collide on
hash if naïvely stringified. Conformant implementations MUST wrap
such values with a type marker BEFORE serialization, so that
distinguishable source values produce distinguishable canonical
bytes.

The wrapper format is:

```json
{"__t__": "<type_name>", "v": <encoded_value>}
```

### Normative `__t__` table

Implementations in any language MUST emit the EXACT wire-level
`__t__` strings from this table — regardless of what the source
language's own type names are. The reference implementation's
Python type names happen to match, but the spec values below are
normative.

| Source-language type | Wire `__t__` value | `v` encoding |
|---|---|---|
| Timestamp with time zone (Python `datetime`, Java `Instant`/`OffsetDateTime`, Go `time.Time`, Rust `chrono::DateTime`) | `"datetime"` | RFC 3339 string (`YYYY-MM-DDTHH:MM:SS[.f]+ZZ:ZZ`) |
| Calendar date (Python `date`, Java `LocalDate`, Go `civil.Date`) | `"date"` | `YYYY-MM-DD` |
| Time-of-day (Python `time`, Java `LocalTime`) | `"time"` | `HH:MM:SS[.f]` |
| Universally unique identifier (Python `UUID`, Java `java.util.UUID`, Go `uuid.UUID`) | `"UUID"` | Canonical lowercase hyphenated form (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) |
| Raw bytes / byte array | `"bytes"` | Lowercase hex string |
| Set of strings | `"set"` | JSON array of the set elements, sorted byte-lexicographically ascending |

**Sets in v0.1 MUST contain only strings.** The reference
implementation uses `sorted(o, key=repr)` which is language-dependent
for non-string elements; v0.1 narrows the constraint to strings-only
so byte-lexicographic ordering is unambiguous. Heterogeneous sets
(e.g. `{1, "1"}`) are NOT defined in v0.1 — implementations MUST
either reject them or canonicalize them as JSON arrays without the
`__t__: set` wrapper (and accept that the resulting payload_hash
will not interop).

Any other non-JSON-native value type is OUT OF SCOPE for v0.1.
Implementations MUST raise / return an error rather than emit a
non-standard `__t__` value (this prevents silent interop divergence
on, e.g., Python `Decimal` vs Java `BigDecimal`).

## Test vectors

Reference test vectors live at
[`test-vectors/canonicalization/`](./test-vectors/canonicalization/).
Each vector is a JSON file with:

```json
{
  "name":          "<short identifier>",
  "input":         <the payload object>,
  "canonical":     "<the canonical UTF-8 string, escaped where needed>",
  "payload_hash":  "<SHA-256 hex of canonical bytes>"
}
```

Conformant implementations MUST produce byte-identical `canonical`
output and matching `payload_hash` for every published vector.

## Worked example

Input payload:

```python
{"b": 1, "a": "hello", "ts": datetime(2026, 1, 1, tzinfo=timezone.utc)}
```

Canonical bytes (with key ordering applied + datetime type-tagged):

```
{"a":"hello","b":1,"ts":{"__t__":"datetime","v":"2026-01-01T00:00:00+00:00"}}
```

SHA-256 of those bytes is the `payload_hash`.
