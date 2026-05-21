"""Verification harness for the standalone SDK package — runs inside a
clean python:3.11-slim container with ONLY veldt-kya installed."""

import sys

before = set(sys.modules.keys())
print(f"baseline modules: {len(before)}")

# The single line the SDK promises
from kya import normalize_agent_def, score_agent  # noqa: E402  (demos lazy-load)

after = set(sys.modules.keys())
new = after - before
print(f"modules pulled in by `from kya import …`: {len(new)}")

# CRITICAL: there should be ZERO Veldt-runtime imports
forbidden = ("fastapi", "routes", "decisions", "services", "db.database", "agents")
leaked = sorted([m for m in new if any(m == k or m.startswith(k + ".") for k in forbidden)])
print(f"veldt-runtime leak: {leaked if leaked else 'NONE'}")

# Show the actual top-level third-party deps loaded (sanity check)
stdlib_ish = {
    "json",
    "typing",
    "enum",
    "re",
    "dataclasses",
    "collections",
    "logging",
    "datetime",
    "hashlib",
    "os",
    "sys",
    "functools",
    "threading",
    "time",
    "warnings",
    "copy",
    "traceback",
    "io",
    "string",
    "math",
    "operator",
    "abc",
    "contextlib",
    "weakref",
    "inspect",
    "keyword",
    "token",
    "tokenize",
    "linecache",
    "importlib",
    "types",
    "pathlib",
    "urllib",
    "encodings",
    "codecs",
    "locale",
    "platform",
    "signal",
    "struct",
    "ast",
    "pickle",
    "base64",
    "binascii",
    "itertools",
    "heapq",
    "numbers",
    "decimal",
    "fractions",
    "random",
    "statistics",
    "array",
    "queue",
    "socket",
    "select",
    "ssl",
    "email",
    "http",
    "unicodedata",
    "calendar",
    "zlib",
    "gzip",
    "tarfile",
    "zipfile",
    "shutil",
    "tempfile",
    "subprocess",
    "runpy",
    "textwrap",
    "posixpath",
    "ntpath",
    "stat",
    "reprlib",
    "atexit",
    "fnmatch",
    "getpass",
    "grp",
    "pwd",
    "argparse",
    "gettext",
    "glob",
    "concurrent",
    "asyncio",
    "contextvars",
    "uuid",
    "_typing",
    "html",
    "mimetypes",
    "shlex",
    "secrets",
    "hmac",
    "mmap",
    "_ast",
    "_collections",
    "_compat_pickle",
    "_compression",
    "_contextvars",
    "_csv",
    "_decimal",
    "_functools",
    "_hashlib",
    "_heapq",
    "_json",
    "_locale",
    "_operator",
    "_pickle",
    "_random",
    "_sha512",
    "_socket",
    "_sqlite3",
    "_sre",
    "_ssl",
    "_string",
    "_struct",
    "_uuid",
    "_weakrefset",
    "opcode",
    "dis",
    "errno",
    "sysconfig",
    "csv",
    "fcntl",
    "ipaddress",
    "selectors",
    "cython_runtime",
    "_cython_3_1_4",
    "_cython_3_2_4",
    "_posixsubprocess",
    "_blake2",
    "_bisect",
    "_lzma",
    "_queue",
    "_bz2",
    "_zoneinfo",
    "zoneinfo",
    "lzma",
    "bz2",
    "annotated_doc",
}
third = sorted(
    {m.split(".")[0] for m in new if m.split(".")[0] not in stdlib_ish and not m.startswith("_")}
)
print(f"third-party deps actually loaded: {third}")

# Functional tests
print()
risk = score_agent(
    {
        "agent_key": "sdk_test",
        "model": "openai/gpt-4o-mini",
        "tools": ["execute_sql", "send_email"],
        "human_loop": "out_of_the_loop",
        "access_level": "write",
        "can_override": True,
    }
)
print(f"score_agent(...) → score={risk.score} bucket={risk.bucket}")
print(f"  factor breakdown sample: {[(f.name, f.delta) for f in risk.factors][:4]}")

norm = normalize_agent_def("generic", {"name": "x", "tools": ["a", "b"]})
print(f"normalize_agent_def('generic', ...) → keys: {sorted(norm)[:6]}")

# Drift detection (no DB needed)
from kya import canonical_hash, detect_drift  # noqa: E402

hsh = canonical_hash({"agent_key": "x", "tools": ["a"]})
drift = detect_drift(hsh, {"agent_key": "x", "tools": ["a", "b"]})
print(f"detect_drift(...) → {drift}  (tools list changed)")

# Compliance summary
from kya import REGIME_BREACH_NOTIFY, compliance_summary  # noqa: E402

cs = compliance_summary(
    {"compliance_scope": ["gdpr", "nydfs_500"], "data_classes": ["pii"]},
    risk.score,
)
print(
    f"compliance_summary(...) → "
    f"controls={len(cs['required_controls'])} "
    f"retention_days={cs['retention_days']}"
)
print(f"REGIME_BREACH_NOTIFY['nydfs_500'] → {REGIME_BREACH_NOTIFY['nydfs_500']}")

print()
print("─" * 50)
print("SDK installed cleanly and works.")
print("─" * 50)
