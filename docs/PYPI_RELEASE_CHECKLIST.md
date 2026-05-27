# veldt-kya — PyPI Release Checklist

**Status:** pre-release · gates to clear before `twine upload`
**Date:** 2026-05-21
**Package:** `veldt-kya` (source: `app/agents/kya/`, packaging: `sdk/pyproject.toml`)
**Target:** `0.1.0rc1` → `0.1.0`

## Context

The SDK has been verified end-to-end:

- 23 pytest unit tests pass
- 4×9 cross-backend e2e matrix passes (PostgreSQL / SQLite / DuckDB / MySQL × 9 phases) — `07e24aa`
- 5-phase concurrency load test (20 workers × 50 ops) — `24f8ef1`
- Live integration in vd-app proven
- Schema fix `5bb9574`, dual-write `3d63d77`, in-tenant feedback `b273980`,
  inbound signing `c5f6cf8`, review pass `8e72ec4`

What follows are the gates remaining before `pip install veldt-kya` is safe
for strangers on the internet.

---

## MUST-DO before PyPI (release blockers)

### 1. Define `__version__` on the `kya` module

- **What:** `telemetry.py:171` imports `from . import __version__` but
  `kya/__init__.py` doesn't export one. Telemetry currently reports
  `0.0.0`, masking which SDK build emitted a signal.
- **Why it blocks PyPI:** version drift is unobservable across customer
  installs the moment we ship more than one release.
- **Effort:** 15 min.
- **Verify:** add `__version__ = "0.1.0"` to `kya/__init__.py`, keep it in
  lockstep with `sdk/pyproject.toml` (or read it from
  `importlib.metadata.version("veldt-kya")` with a stdlib fallback).
- **Done when:** `python -c "import kya; print(kya.__version__)"` prints
  the same string as `pip show veldt-kya | grep Version`.

### 2. Decide what `DEFAULT_PINNED_KEYS` ships as

- **What:** `_inbound_signing.py:48` defines an empty `DEFAULT_PINNED_KEYS`
  dict. Until Veldt's collector signing key exists, the SDK has nothing
  to anchor inbound signed recommendations against unless the customer
  sets `KYA_TRUSTED_KEYS` themselves.
- **Why it blocks PyPI:** users `pip install`-ing the inbound path will
  see zero trusted keys and silently no-op. Either the dict ships with
  Veldt's real public key, OR the README must call this out and the
  inbound module must hard-refuse with a clear error.
- **Effort:** 30 min (decision) + 15 min (impl). Real key issuance is
  itself blocked on the collector decision in `kya_collector_roadmap.md`.
- **Verify:** ship one of (a) pinned key from Veldt's KMS, or (b)
  explicit `RuntimeError("no trusted keys configured; set KYA_TRUSTED_KEYS")`
  on first `verify()` call when the map is empty.
- **Done when:** `trusted_keys()` either returns at least one entry by
  default OR the inbound flow refuses with a documented error.

### 3. Cleanroom `pip install` test matrix

- **What:** Build the wheel, install into a fresh venv on Python 3.10,
  3.11, 3.12 across Linux / macOS / Windows. Run the smoke import +
  `score_agent` + `normalize_agent_def` paths.
- **Why it blocks PyPI:** the `package-dir = ["../app/agents"]` setup
  (item 6) is unusual. We do not know what the wheel actually contains
  without building it. Wheels-from-strange-layouts have surfaced missing
  `__init__.py` files and silent module exclusions in the past.
- **Effort:** 1-2 hrs once CI matrix is wired.
- **Verify:**
  ```
  python -m build --wheel sdk/
  pip install dist/veldt_kya-0.1.0-*.whl
  python -c "import kya; kya.score_agent(kya.normalize_agent_def('veldt', {'agent_key':'x'}))"
  ```
  Run on all 9 combinations (3 Python × 3 OS).
- **Done when:** all 9 matrix cells pass; wheel contents (`unzip -l`)
  show every kya submodule the source tree has, nothing from
  `kya_redteam` or `tests/`.

### 4. Sweep `.kya_test/` and tests directory for real secrets

- **What:** Tests historically use real `.env` overrides and may have
  written test fixtures containing real Keycloak tokens, real database
  URIs, or real OpenAI keys to `.kya_test/`.
- **Why it blocks PyPI:** sdists pick up everything not in
  `MANIFEST.in` exclusions. A leaked `.env` in a published wheel is
  unrecoverable — PyPI does not support deletion-with-yank-and-rotate.
- **Effort:** 30 min.
- **Verify:**
  ```
  python -m build --sdist sdk/
  tar tzf dist/veldt_kya-0.1.0.tar.gz | grep -E '\.env|secret|token|\.kya_test'
  trufflehog filesystem dist/
  ```
- **Done when:** `trufflehog` returns clean AND manual sdist listing
  shows zero `.env` / `.kya_test/` / `*credentials*` files.

### 5. License clarity in `pyproject.toml`

- **What:** `sdk/pyproject.toml:14` declares `license = { file = "LICENSE" }`
  with classifier `License :: Other/Proprietary License`. The header
  comment explicitly says "Do NOT publish to PyPI without updating both."
- **Why it blocks PyPI:** PyPI accepts proprietary, but Apache-2.0 / MIT
  is what the agent-governance ecosystem expects from an SDK. Going up
  with "Proprietary" will visibly cap adoption.
- **Effort:** founder decision; impl is 15 min once decided.
- **Verify:** update the `LICENSE` file, the `license` field, and the
  classifier together; consider a `NOTICE` file if Apache-2.0.
- **Done when:** `pip install veldt-kya` followed by `pip show
  veldt-kya | grep License` reports the intended license; SPDX
  identifier matches.

### 6. SDK works without parent `app/` directory present

- **What:** `sdk/pyproject.toml` uses `package-dir = ["../app/agents"]`.
  This works for `pip install -e ./sdk` against the monorepo, but the
  PyPI install path must work in isolation — the customer machine has
  no `app/agents/` sibling.
- **Why it blocks PyPI:** if the wheel was built from the monorepo but
  the runtime resolves any path back into `../app/`, installs on a
  bare machine will `ImportError`. Likely fine (the wheel snapshots the
  source), but unverified.
- **Effort:** 30 min — bundled with item 3.
- **Verify:** install the wheel into a venv on a machine with NO
  `veldt-decisions` checkout, run the smoke imports, run one
  end-to-end scoring call.
- **Done when:** smoke test passes in `/tmp` with no parent `app/`
  directory anywhere on `sys.path`.

---

## SHOULD-DO before PyPI (strongly recommended)

### 7. Error injection tests

- **What:** malformed signed-recommendation payloads, partial network
  failures during dual-write, missing optional deps (`prometheus_client`
  absent when `kya.metrics` is imported), missing collector keys.
- **Why:** catches the "happy path tests pass, real customers hit weird
  failure modes" class of issues that bring early SDKs into disrepute.
- **Effort:** 2-3 hrs.
- **Verify:** add `tests/test_error_paths.py` covering each failure
  branch with explicit assertions on log lines + exception types.
- **Done when:** every `except` block in `kya/` is exercised by at
  least one test and the SDK degrades gracefully (no uncaught
  exceptions escape SDK boundaries).

### 8. Daemon thread + `atexit` lifecycle

- **What:** outbound telemetry and dual-write use daemon threads + an
  `atexit` flush hook. Enable / disable cycles in a long-running host
  process (Jupyter, Airflow worker) could leak threads or stack
  duplicate atexit handlers.
- **Why:** silent thread leaks bite production users 3 months in.
- **Effort:** 1 hr.
- **Verify:**
  ```
  for _ in range(100): kya.enable_telemetry(); kya.disable_telemetry()
  assert threading.active_count() == baseline
  assert len(atexit._exithandlers) == baseline_atexit
  ```
- **Done when:** thread + atexit handler counts are stable across 100
  enable/disable cycles.

### 9. Optional extras install matrix

- **What:** `pip install veldt-kya[metrics]`, `[tracing]`, `[webhooks]`,
  `[judge]`, `[all]` all resolve and the gated imports actually wake up.
- **Why:** extras are the contract surface for opt-in features; a
  broken `[judge]` extra silently disables the LLM-as-judge adapters
  (`arize_phoenix` + `openai_judge` via litellm) in the orchestrator.
- **Effort:** 30 min.
- **Verify:** install each extra into a fresh venv, then
  `python -c "import litellm; from kya.scorer_orchestrator import register_phoenix_adapter; register_phoenix_adapter()"` etc.
- **Done when:** every extra installs cleanly and unlocks the
  capability gate it claims to unlock.

### 10. Wheel-install behavioral parity with source-tree import

- **What:** every test that passes against `app/agents/kya` must also
  pass when the same test imports `kya` from the installed wheel.
- **Why:** the wheel is the actual product. Source-tree-only tests
  give false confidence.
- **Effort:** 1 hr (parameterize the existing test suite via a
  `KYA_IMPORT_MODE=wheel` env switch).
- **Done when:** the 23-test unit suite + 4×9 e2e matrix both pass
  with `KYA_IMPORT_MODE=wheel` in CI.

---

## CAN-WAIT (post-v0.1)

- Multi-tenant scaling load test (>4 backends, >20 workers)
- Long-running stability soak (12-72 hrs continuous)
- DuckDB legacy-table limitation — already documented, known constraint
- `SECURITY.md` + advisory disclosure channel — needed before v1.0, not v0.1
- SLSA attestation + OIDC trusted publishing — see "Hygiene" below

---

## PyPI hygiene (do alongside the must-dos)

| Item | Why | How to verify |
|---|---|---|
| Name conflict check on PyPI | `veldt-kya` must be ungrabbed and not typosquat-adjacent to a popular package | `pip index versions veldt-kya` returns "no matching" + manual check of `kya`, `veldt`, `veldt-agents` |
| Trademark / brand on "KYA" | Vouched raised on a "KYA" thesis (see `project_kya_competitors_funding.md`); confirm we have freedom to ship under this name | USPTO TESS search; check Vouched's filings |
| Pre-release tag flow | Cut `0.1.0rc1` first, get feedback from 3 friendlies, then `0.1.0` | `pip install --pre veldt-kya` resolves to rc; subsequent `pip install veldt-kya` resolves to GA |
| `CHANGELOG.md` | Customers need to know what changed between rc1 and GA without git archaeology | Keep-a-Changelog format; one entry per `c5f6cf8`/`8e72ec4`/`07e24aa`/`24f8ef1` etc. |
| GitHub Actions trusted publishing | Avoid long-lived PyPI API tokens; use OIDC from a tag-gated workflow | `.github/workflows/publish.yml` triggered on `v*` tag, `id-token: write`, no `PYPI_API_TOKEN` secret needed |

---

## Suggested order of operations

1. Items 1, 2, 5 (decisions + small code changes) — 1 afternoon
2. Items 4, 6 + sdist build — 1 afternoon
3. Item 3 cleanroom matrix + item 10 wheel parity — wire CI once, runs
   forever after
4. Items 7, 8, 9 — 1 day combined
5. Hygiene table — alongside, none blocks the others
6. Tag `0.1.0rc1`, publish via trusted publishing, collect feedback
7. Tag `0.1.0`, publish, announce

Total realistic time to PyPI: **2-3 focused days** assuming the license
decision (item 5) and trust-key decision (item 2) are not blocked on
external approval.
