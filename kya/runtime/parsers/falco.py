"""Falco -> KYA RuntimeEvent parser.

Falco (https://falco.org/) is the CNCF runtime-security project. It
emits JSON over stdout / unix socket / gRPC; this module translates
that JSON into KYA's canonical :class:`RuntimeEvent`. The collector
that feeds this parser is the user's responsibility (Falco sidecar,
``falcoctl``, fluentbit -> webhook, anything that can stream NDJSON).

Falco JSON shape (the parts that matter)
----------------------------------------
A Falco alert looks like::

    {
      "output": "Notice Shell spawned in a container with an established outbound connection",
      "priority": "Warning",
      "rule": "Terminal shell in container",
      "time": "2024-01-15T10:23:45.123456789Z",
      "output_fields": {
        "container.id": "abcd1234",
        "container.image.repository": "alpine",
        "container.name": "happy_curie",
        "evt.time": 1705314225000000000,
        "k8s.ns.name": "production",
        "k8s.pod.name": "checkout-7f8b9c-x2k",
        "proc.cmdline": "sh -i",
        "proc.name": "sh",
        "proc.pid": 12345,
        "proc.pname": "containerd-shim",
        "proc.ppid": 1234,
        "user.name": "root",
        "user.uid": 0
      },
      "tags": ["container", "mitre_execution", "shell"],
      "hostname": "node-01",
      "source": "syscall"
    }

That's the public, documented shape -- the same one used by Falco's
JSON-output drivers and by ``falcosidekick``.

Action vocabulary
-----------------
Falco's ``rule`` strings are human-readable and unstable across
versions; we don't translate them into canonical action verbs. The
parser sets ``action`` to a stable derived value from the rule name
in snake_case so attack-chain rules can match on it cross-version.
Operators who need version-pinned matching should match on
``source_rule_id`` directly.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

from .._canonical import (
    PrincipalHint,
    ProcessRef,
    RuntimeEvent,
    RuntimeSeverity,
)

logger = logging.getLogger(__name__)


# Falco priority -> KYA severity. Falco docs:
# https://falco.org/docs/concepts/rules/falco-rules/ -- the priority
# field is the canonical severity signal.
_PRIORITY_MAP: dict[str, RuntimeSeverity] = {
    "emergency": "critical",
    "alert": "critical",
    "critical": "critical",
    "error": "high",
    "warning": "high",
    "notice": "medium",
    "informational": "informational",
    "info": "informational",
    "debug": "informational",
}


def can_parse(raw: dict) -> bool:
    """Cheap shape check: Falco JSON has ``rule`` + ``output_fields``
    + ``priority`` at the top level. We don't require ``source`` to
    avoid drift across versions, but the combo of all three is
    Falco-distinctive enough that we won't false-positive on
    Tetragon / k8s-audit.
    """
    if not isinstance(raw, dict):
        return False
    return (
        isinstance(raw.get("rule"), str)
        and isinstance(raw.get("output_fields"), dict)
        and isinstance(raw.get("priority"), str)
    )


def _parse_time(raw: dict) -> float:
    """Falco's ``time`` is RFC3339 ns-precision. Fall back to
    ``output_fields["evt.time"]`` (nanoseconds since epoch) if the
    top-level string is missing or unparsable.

    Returns Unix epoch seconds as a float -- monotonic per source.
    On total failure returns ``0.0`` (the bridge will still ingest,
    attack-chain windows simply won't match -- failing soft).
    """
    t = raw.get("time")
    if isinstance(t, str) and t:
        try:
            # RFC3339 with optional nanosecond precision. Python's
            # fromisoformat handles ``Z`` since 3.11; for 3.10 we
            # strip it manually.
            cleaned = t.rstrip("Z")
            if cleaned.endswith("+00:00"):
                pass
            elif "+" not in cleaned and cleaned.count(":") >= 2:
                # No tz -> assume UTC (Falco default).
                pass
            # Truncate sub-microsecond precision; datetime can't
            # carry nanoseconds and the bridge's window granularity
            # is seconds anyway.
            if "." in cleaned:
                head, frac = cleaned.split(".", 1)
                # keep up to 6 fractional digits
                tz_split = re.split(r"([+-]\d{2}:\d{2})$", frac, maxsplit=1)
                frac_digits = tz_split[0][:6]
                tail = "".join(tz_split[1:])
                cleaned = f"{head}.{frac_digits}{tail}"
            dt = datetime.fromisoformat(cleaned)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except (ValueError, TypeError):
            logger.debug("[KYA-FALCO] unparseable time field: %r", t)

    of = raw.get("output_fields") or {}
    ns = of.get("evt.time")
    if isinstance(ns, (int, float)) and ns > 0:
        return float(ns) / 1_000_000_000.0
    return 0.0


def _action_from_rule(rule_name: str) -> str:
    """Stable snake_case action verb derived from the Falco rule
    name. Falco rule names are human strings (``"Terminal shell in
    container"``); we lowercase, replace non-word chars with ``_``,
    collapse runs. This isn't perfect but it's stable across Falco
    minor versions, which is what attack-chain rules need.
    """
    s = re.sub(r"[^a-z0-9]+", "_", rule_name.strip().lower())
    s = s.strip("_")
    return s or "falco_event"


def _principal_hints(of: dict[str, Any]) -> tuple[PrincipalHint, ...]:
    """Extract every binding hint Falco's output_fields can yield.

    The bridge tries hints in order. We list the strongest first:
    explicit Veldt label > k8s SA > process user.
    """
    hints: list[PrincipalHint] = []

    label = of.get("container.label.io.veldt.principal_id")
    if isinstance(label, str) and label.strip():
        hints.append(PrincipalHint(
            kind="container_label", value=label.strip()))

    sa_name = of.get("k8s.sa.name") or of.get("k8s.pod.serviceaccount.name")
    ns = of.get("k8s.ns.name")
    if isinstance(sa_name, str) and sa_name.strip():
        ns_part = (
            ns.strip()
            if isinstance(ns, str) and ns.strip()
            else "default"
        )
        hints.append(PrincipalHint(
            kind="service_account",
            value=f"{ns_part}/{sa_name.strip()}",
        ))

    user = of.get("user.name")
    if isinstance(user, str) and user.strip():
        hints.append(PrincipalHint(
            kind="process_user", value=user.strip()))

    return tuple(hints)


def _process_ref(of: dict[str, Any]) -> ProcessRef | None:
    """Build a ProcessRef from Falco's ``output_fields`` if any of the
    relevant keys are present. Returns ``None`` when no process info
    was emitted (some Falco rules don't bind to a process)."""
    name = of.get("proc.name")
    cmdline = of.get("proc.cmdline")
    pid = of.get("proc.pid")
    ppid = of.get("proc.ppid")
    user = of.get("user.name")
    uid = of.get("user.uid")
    image = of.get("proc.exepath") or of.get("proc.exe")

    if not any([name, cmdline, pid, ppid, user, image]):
        return None

    return ProcessRef(
        image=str(image) if image else None,
        name=str(name) if name else None,
        cmdline=str(cmdline) if cmdline else None,
        pid=int(pid) if isinstance(pid, (int, float)) and pid >= 0 else None,
        ppid=(
            int(ppid)
            if isinstance(ppid, (int, float)) and ppid >= 0 else None
        ),
        user=str(user) if user else None,
        uid=int(uid) if isinstance(uid, (int, float)) and uid >= 0 else None,
    )


def parse(raw: dict) -> RuntimeEvent | None:
    """Translate one Falco JSON alert into a canonical RuntimeEvent.

    Returns ``None`` on payloads that don't match the Falco shape.
    Raises only on programming errors -- corrupt input is logged at
    debug and dropped (the bridge fails soft on the parser layer).
    """
    if not can_parse(raw):
        return None

    rule = str(raw["rule"])
    priority = str(raw["priority"]).strip().lower()
    severity: RuntimeSeverity = _PRIORITY_MAP.get(priority, "low")

    output = str(raw.get("output", ""))
    of = raw.get("output_fields") or {}
    if not isinstance(of, dict):
        of = {}

    container_id = of.get("container.id")
    container_image = (
        of.get("container.image.repository")
        or of.get("container.image")
    )
    pod_name = of.get("k8s.pod.name")
    namespace = of.get("k8s.ns.name")
    node = raw.get("hostname")

    tags_raw = raw.get("tags") or []
    tags = tuple(t for t in tags_raw if isinstance(t, str))

    return RuntimeEvent(
        source_tool="falco",
        source_rule_id=rule,
        occurred_at_ts=_parse_time(raw),
        severity=severity,
        action=_action_from_rule(rule),
        message=output,
        container_id=(
            str(container_id) if isinstance(container_id, str) else None
        ),
        container_image=(
            str(container_image)
            if isinstance(container_image, str) else None
        ),
        pod_name=str(pod_name) if isinstance(pod_name, str) else None,
        namespace=str(namespace) if isinstance(namespace, str) else None,
        node=str(node) if isinstance(node, str) else None,
        process=_process_ref(of),
        principal_hints=_principal_hints(of),
        tags=tags,
        raw=dict(raw),  # detach from caller's dict
    )
