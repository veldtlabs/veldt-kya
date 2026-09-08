"""Every output block in the README must be what the examples print.

Why this exists
---------------
The README shows result blocks - verdicts, amounts, chain names - and
claims ``examples/quickstart`` reproduces them. That claim rots the
moment either side changes, and it rots silently: the README keeps
looking authoritative while the code prints something else.

It had already rotted before this test existed. Six blocks disagreed
with the script, including an identity section the script never
produced at all, and a hand-checked "I ran it and the numbers matched"
missed every one of them - because checking a handful of expected
values is not the same as diffing every line.

So this asserts the whole set mechanically: run the examples for real,
then require each line of each unlabelled fence in the README to appear
in that output. Editorial annotations after ``<-`` are ignored; the
text to their left is not.

This is slow (it starts a gateway and a stub tool). That is the price
of the README being true.
"""
from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_QUICKSTART = _ROOT / "examples" / "quickstart"
_README = _ROOT / "README.md"

# The examples bind these; a busy port means the run would silently
# measure someone else's server.
_PORTS = (8098, 8099, 9099)


def _port_free(port: int) -> bool:
    import socket

    probe = socket.socket()
    try:
        probe.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def _output_blocks(markdown: str) -> list[list[str]]:
    """Unlabelled ``` fences only - those are result blocks. Fences
    tagged python/yaml/bash/text are source, not output."""
    blocks: list[list[str]] = []
    current: list[str] | None = None
    lang = ""
    for line in markdown.splitlines():
        if line.startswith("```"):
            if current is None:
                lang, current = line[3:].strip(), []
            else:
                if lang == "":
                    blocks.append(current)
                current, lang = None, ""
        elif current is not None:
            current.append(line)
    return blocks


def _normalise(text: str) -> str:
    return " ".join(text.split())


@pytest.fixture(scope="module")
def example_output(tmp_path_factory) -> str:
    if not _QUICKSTART.exists():
        pytest.skip("examples/quickstart is not present")
    busy = [p for p in _PORTS if not _port_free(p)]
    if busy:
        pytest.skip(f"ports in use: {busy}")

    workdir = tmp_path_factory.mktemp("quickstart")
    for item in _QUICKSTART.iterdir():
        if item.is_file():
            shutil.copy2(item, workdir / item.name)

    # run.py writes UTF-8 deliberately; decoding with the locale codec
    # turns an em dash into a replacement char and the comparison below
    # then fails on a difference that does not exist.
    proc = subprocess.run(
        [sys.executable, "run.py"], cwd=workdir,
        capture_output=True, text=True, timeout=600,
        encoding="utf-8", errors="replace",
    )
    assert proc.returncode == 0, (
        f"examples/quickstart/run.py exited {proc.returncode}. The README "
        f"tells readers to run this.\n{proc.stdout[-3000:]}\n{proc.stderr[-2000:]}"
    )
    if "to run this one" in proc.stdout:
        pytest.skip(
            "attack-chain engine unavailable in this environment, so the "
            "examples skip section 5. Install veldt-kya[attack_chains] and "
            "make sure `import kya` resolves to it, not an older copy.")
    return proc.stdout


def test_every_readme_output_line_is_really_printed(example_output):
    printed = {_normalise(line) for line in example_output.splitlines()}
    blocks = _output_blocks(_README.read_text(encoding="utf-8"))
    assert blocks, "no output blocks found in the README"

    missing = []
    checked = 0
    for block in blocks:
        for line in block:
            # An editorial annotation may follow "<-"; what precedes it
            # is quoted output and must be real.
            claim = _normalise(line.split("<-")[0])
            if not claim:
                continue
            checked += 1
            if claim not in printed:
                missing.append(claim)

    assert checked, "no output lines were checked - is the parser wrong?"
    assert not missing, (
        "the README shows output the examples do not print:\n  "
        + "\n  ".join(missing)
        + "\n\nEither fix the README or fix examples/quickstart. A README "
          "that quotes output nobody can reproduce is worse than one that "
          "quotes none."
    )


def test_the_examples_do_not_warn_about_their_own_configuration(
    example_output,
):
    """A warning in the output is a defect the reader sees first.

    The demo signing key was once not valid base64, so every run opened
    with 'invalid signing key' and evidence silently fell back to a
    process-local key - the exact thing the evidence example claims to
    demonstrate. It survived because the checks at the time grepped for
    expected lines instead of reading what was printed.
    """
    for marker in ("invalid signing key",
                   "no KYA_EVIDENCE_KEY_PROVIDER",
                   "Traceback"):
        assert marker not in example_output, (
            f"the examples print {marker!r}, which every reader sees:\n"
            + example_output[-2000:]
        )
