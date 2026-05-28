---
name: Bug report
about: Report something KYA does wrong, crashes, or fails to do as documented
title: '[bug] '
labels: bug
assignees: ''
---

## Summary

<!-- One sentence: what did you expect, what happened instead. -->

## Reproduction

KYA version: <!-- `pip show veldt-kya` -->
Python version: <!-- `python --version` -->
Storage backend: <!-- PostgreSQL / MySQL / SQLite / DuckDB -->
Framework adapter (if applicable): <!-- LangChain / CrewAI / OpenAI Agents / Claude SDK / etc. -->

Minimal reproduction:

```python
# Paste the smallest possible snippet that demonstrates the bug.
# If it requires a DB, please use SQLite — easier for us to repro.
```

Steps to trigger:

1. <!-- ... -->
2. <!-- ... -->

## Expected behavior

<!-- What you expected KYA to do. -->

## Actual behavior

<!-- What KYA actually did. Paste any tracebacks, log lines, or scored output below. -->

```
<!-- traceback / output / etc. -->
```

## Additional context

<!-- Anything else worth knowing: tenant configuration, agent definition, signal counts, environment variables (KYA_*), etc. -->

## Security-sensitive?

If this bug has security implications (auth bypass, tenant leak, evidence-chain tamper, etc.), **stop and use [SECURITY.md](../SECURITY.md) instead.** Don't disclose in a public issue.
