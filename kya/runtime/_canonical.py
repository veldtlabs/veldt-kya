"""Canonical runtime-security event types.

Every parser in ``kya.runtime.parsers.*`` produces values of these
types -- no exceptions. The bridge knows nothing about Falco vs
Tetragon JSON shapes; it only knows :class:`RuntimeEvent`.

Choosing this contract carefully matters: it's the seam between the
heterogeneous OSS runtime-security ecosystem and KYA's stable internal
model. Future parsers (Tetragon, Tracee, osquery, ...) must be
expressible without adding tool-specific fields here -- if a new tool
needs something the contract can't represent, we extend the contract
deliberately, not the parser.

Design rules
------------
* Frozen + slotted dataclasses; the canonical event is immutable
  evidence by the time the bridge sees it.
* No persistence concerns. The bridge layer does evidence-chain attach
  and attack-chain dispatch; this module is pure data.
* No cross-parser imports. Importing :mod:`kya.runtime` does NOT pull
  any runtime-security tool's SDK.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

# ── Source-of-truth enums ──────────────────────────────────────────

#: The complete set of runtime-security sources KYA knows how to bind
#: to a principal. Adding a value here is a deliberate contract change
#: -- not every parser needs a new tag, but every tag needs a parser.
SourceTool = Literal[
    "falco",       # CNCF runtime security
    "tetragon",    # Isovalent eBPF
    "tracee",      # Aqua Security eBPF
    "sysdig",      # Sysdig OSS (Falco's precursor)
    "osquery",     # Host queries / scheduled snapshots
    "auditd",      # Linux audit subsystem
    "k8s_audit",   # Kubernetes API-server audit log
    "ebpf",        # Custom eBPF probes (user-emitted)
]

#: Five-level severity normalised across tools. Each parser maps its
#: native level (Falco's "Critical", Tetragon's policy match, etc.)
#: into one of these. "informational" exists so we never silently drop
#: a low-severity event -- the bridge can still bind+attach it.
RuntimeSeverity = Literal[
    "informational",
    "low",
    "medium",
    "high",
    "critical",
]

#: How a parser tells the bridge to bind this event to a principal.
#: The bridge layer owns the binding *strategy*; the parser just hands
#: over what it knows from the raw payload.
PrincipalHintKind = Literal[
    "container_label",   # parsed container has a `io.veldt.principal_id` label
    "service_account",   # k8s SA name + namespace
    "spiffe_id",         # SPIFFE / SVID-style URI
    "process_user",      # uid / username only (weakest binding)
    "explicit",          # caller already resolved the principal
    "unknown",           # parser could not extract any hint
]


# ── Sub-records ────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ProcessRef:
    """Identifying details for the process that triggered the alert.

    All fields are best-effort. Falco's ``proc.cmdline`` may include
    the full argv; auditd may only have ``comm``. Parsers fill what
    they have and leave the rest ``None``.
    """

    image: str | None = None
    pid: int | None = None
    ppid: int | None = None
    name: str | None = None       # short comm / basename
    cmdline: str | None = None    # full argv as a single string
    user: str | None = None
    uid: int | None = None


@dataclass(frozen=True, slots=True)
class PrincipalHint:
    """How the parser thinks this event should bind to a KYA principal.

    The bridge applies a configurable strategy chain (label -> SA ->
    SPIFFE -> process_user -> drop) over these hints; multiple hints
    of different kinds may be present on one event.

    `value` shape per kind:
        container_label -> the label *value* (e.g. ``"agent_42"``)
        service_account -> ``"<namespace>/<sa_name>"``
        spiffe_id       -> the SPIFFE URI
        process_user    -> the username
        explicit        -> the KYA principal_id directly
        unknown         -> empty string (kept to keep the hint typed)
    """

    kind: PrincipalHintKind
    value: str


# ── Canonical event ────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class RuntimeEvent:
    """One runtime-security alert, normalised across all source tools.

    Required:
        source_tool    Which OSS source emitted this (see SourceTool).
        source_rule_id The tool's own rule identifier (Falco rule
                       name, Tetragon policy name, ...). Preserved so
                       the operator can grep the original ruleset.
        occurred_at_ts Unix epoch seconds, float. Bridge correlates
                       across events using this, so monotonicity per
                       source matters.
        severity       Normalised severity (see RuntimeSeverity).
        action         A short canonical verb describing what
                       happened: ``"shell_in_container"``,
                       ``"sensitive_file_read"``, ``"network_out"``,
                       ``"exec_from_writable_dir"``. Parsers choose
                       from a documented vocabulary; unknown verbs are
                       allowed but won't match shipped attack-chain
                       rules.
        message        Human-readable summary (Falco ``output``,
                       Tetragon ``policy.message``, ...).

    Optional (any may be None / empty):
        container_id, container_image, pod_name, namespace, node:
            Container / k8s context.
        process:
            ProcessRef -- best-effort process metadata.
        principal_hints:
            Tuple of hints; the bridge tries them in order until one
            resolves. Empty tuple means "no hint -- bridge applies
            fall-back strategies or drops".
        tenant_id, principal_id:
            Pre-resolved values from the caller. When set, the bridge
            SKIPS its binding strategies and uses these directly.
        tags:
            MITRE technique IDs, vendor tags (``mitre_persistence``,
            ``defense_evasion``, ...). Surfaced through to evidence
            metadata.
        raw:
            The full original payload. Kept verbatim so the evidence
            chain can hash + sign the exact source bytes (auditor
            requirement).
    """

    source_tool: SourceTool
    source_rule_id: str
    occurred_at_ts: float
    severity: RuntimeSeverity
    action: str
    message: str

    container_id: str | None = None
    container_image: str | None = None
    pod_name: str | None = None
    namespace: str | None = None
    node: str | None = None

    process: ProcessRef | None = None

    principal_hints: tuple[PrincipalHint, ...] = field(default_factory=tuple)

    tenant_id: str | None = None
    principal_id: str | None = None

    tags: tuple[str, ...] = field(default_factory=tuple)

    raw: dict[str, Any] = field(default_factory=dict)
