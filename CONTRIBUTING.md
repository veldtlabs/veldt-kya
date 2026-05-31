# Contributing to KYA

Thanks for considering a contribution. KYA is open-source (Apache 2.0) and we welcome bug reports, framework adapters, attack-chain rules, compliance regime mappings, and documentation improvements.

## Quick start (development)

```bash
git clone https://github.com/veldtlabs/veldt-kya.git
cd veldt-kya
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[all]"
pip install pytest mypy ruff   # dev tools
pytest                          # 0 failures expected on a clean clone
```

KYA targets **Python 3.10+** and runs against PostgreSQL, MySQL, SQLite, and DuckDB. Most local development uses SQLite by default — no extra setup.

## Where to contribute

| You want to... | Look here |
|---|---|
| Fix a bug | Open an issue first if it's non-trivial; PR welcome for trivial fixes |
| Add a framework adapter (e.g., a new agent SDK) | `kya/format_adapter.py` — see the dispatch table at the bottom |
| Add a judge (safety / faithfulness / data-leak detector) | `kya/scorer_orchestrator.py` — implement the `Judge` protocol |
| Add a compliance regime mapping | `kya/compliance.py` |
| Add a red-team attack-chain rule | `kya_redteam/` (separate package) |
| Improve documentation | `docs/` or the README |
| Add framework integration examples | `examples/` |

## Pull request process

1. **Open an issue first** if your change is non-trivial (>50 lines, public API change, new dependency). Saves both of us time.
2. **Branch naming**: `fix/short-description`, `feat/short-description`, `docs/short-description`.
3. **Tests**: any new code needs at least one pytest. Run `pytest` locally before opening the PR.
4. **Style**: we use `ruff` for linting and `mypy` for type checking. Run `ruff check . && ruff format . && mypy kya` before pushing.
5. **Commits**: keep them focused. Squash on merge is the default.
6. **CHANGELOG.md**: add an entry under `## Unreleased` describing your change (one line).
7. **PR description**: fill out the template that auto-loads.

## Things we appreciate

- Tests that demonstrate behavior, not just exercise coverage
- Examples in `examples/` showing how to use new features
- Docstrings on public functions explaining the *why*, not just the *what*
- Honest acknowledgment of scope and trade-offs

## Things we don't merge

- Code without tests
- Public-API changes without a corresponding `docs/` update
- New runtime dependencies for `kya` core (the SDK has a deliberately small dependency surface). New deps belong in optional extras (`[redteam]`, `[judges]`, etc.).
- AI-generated code without human review (be explicit if you used an AI assistant)

## Maintainers

Maintained by [Veldt Labs](https://veldtlabs.ai). Questions: open a [Discussion](https://github.com/veldtlabs/veldt-kya/discussions) or email kola@veldtlabs.ai.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By contributing you agree to abide by it.
