"""Canonical event types for the KYA runtime bridge.

Two event shapes live here, both consumed by the same bridge:

* :class:`RuntimeEvent` — container / k8s / host runtime-security alerts
  (Falco, Tetragon, Tracee, Sysdig OSS, osquery, auditd, k8s-audit,
  custom eBPF). Carries container_id, ProcessRef, pod/namespace.
* :class:`AutonomyEvent` — autonomous-system events (MAVLink today;
  ROS2 / DDS / OPC-UA / PX4 follow the same pattern). Carries
  VehicleRef and geo / mission context instead of container metadata.

Both satisfy the structural :class:`BoundEvent` protocol — the bridge
routes any object exposing the protocol's attributes, so adding a
third event family in the future (industrial, network, ...) does not
touch the bridge or existing parsers.

Design rules
------------
* Frozen + slotted dataclasses; canonical events are immutable
  evidence by the time the bridge sees them.
* No persistence concerns. The bridge does evidence-chain attach and
  attack-chain dispatch; this module is pure data.
* No cross-parser imports. Importing :mod:`kya.runtime` does NOT pull
  any runtime-security or autonomy SDK.
* Protocol is for type contracts, not isinstance hot-path checks.
  ``runtime_checkable`` walks ``__annotations__`` and is ~50× slower
  than concrete isinstance — use it at API boundaries / tests only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, Sequence, runtime_checkable

# ── Source-of-truth enums ──────────────────────────────────────────

#: Runtime-security tools. Each maps to a parser in
#: ``kya.runtime.parsers.<name>`` (open SDK) or
#: ``kya_pro.parsers.<name>`` (commercial overlay).
RuntimeSecurityTool = Literal[
    "falco",       # CNCF runtime security
    "tetragon",    # Isovalent eBPF
    "tracee",      # Aqua Security eBPF
    "sysdig",      # Sysdig OSS (Falco's precursor)
    "osquery",     # Host queries / scheduled snapshots
    "auditd",      # Linux audit subsystem
    "k8s_audit",   # Kubernetes API-server audit log
    "ebpf",        # Custom eBPF probes (user-emitted)
]

#: Autonomous-system protocols. Same shape, different ontology:
#: parsers consume protocol streams (MAVLink, ROS2 topics, OPC-UA
#: nodes) and emit :class:`AutonomyEvent`.
AutonomyTool = Literal[
    "mavlink",     # MAVLink 1.0 / 2.0 (ArduPilot, PX4)
    # ros2, dds, opcua follow the same pattern when their parsers ship
]

#: Union of every source the bridge currently knows about. Adding a
#: value is a deliberate contract change — every value MUST have a
#: parser registered before it is shipped.
SourceTool = RuntimeSecurityTool | AutonomyTool

#: Two top-level event families. Downstream consumers (dashboards,
#: filters, evidence-kind tagging) read this off the bridge result
#: rather than enumerating SourceTool values — when ROS2 / OPC-UA
#: parsers ship, their dashboards keep working unchanged.
SourceKind = Literal["runtime_security", "autonomy"]


def source_kind_of(tool: SourceTool) -> SourceKind:
    """Classify a SourceTool into its event family.

    Pure mapping — kept here so dashboards and the bridge agree on
    the classification without re-encoding it.
    """
    if tool == "mavlink":
        return "autonomy"
    return "runtime_security"


#: Five-level severity normalised across tools. Each parser maps its
#: native level (Falco's "Critical", Tetragon's policy match,
#: MAVLink's STATUSTEXT severity, ...) into one of these.
#: "informational" exists so we never silently drop a low-severity
#: event — the bridge can still bind + attach it.
RuntimeSeverity = Literal[
    "informational",
    "low",
    "medium",
    "high",
    "critical",
]

#: How a parser tells the bridge to bind this event to a principal.
#: The bridge layer owns the binding *strategy*; the parser just
#: hands over what it knows from the raw payload.
PrincipalHintKind = Literal[
    # Container / k8s / host
    "container_label",   # parsed container has a `io.veldt.principal_id` label
    "service_account",   # k8s SA name + namespace
    "spiffe_id",         # SPIFFE / SVID-style URI (covers x509 SVID; MAVLink Auth signed packets also land here)
    "process_user",      # uid / username only (weakest binding)
    # Autonomous systems
    "vehicle_id",        # opaque fleet-configured vehicle identifier
    "mavlink_sysid",     # encoded "<sysid>:<compid>" pair (see encode_mavlink_sysid)
    # Universal
    "explicit",          # caller already resolved the principal
    "unknown",           # parser could not extract any hint
]


# ── Encoding helpers ───────────────────────────────────────────────


def encode_mavlink_sysid(sysid: int, compid: int) -> str:
    """Canonical encoding of a MAVLink (sysid, compid) pair as the
    string value of a ``PrincipalHint(kind="mavlink_sysid", ...)``.

    Co-located with the consumer (``MavlinkSysidResolver``) so the
    encoding cannot drift across producer and consumer.
    """
    if not (0 <= sysid <= 255 and 0 <= compid <= 255):
        raise ValueError(
            f"MAVLink sysid/compid out of range [0, 255]: "
            f"sysid={sysid}, compid={compid}")
    return f"{sysid}:{compid}"


def decode_mavlink_sysid(value: str) -> tuple[int, int] | None:
    """Inverse of :func:`encode_mavlink_sysid`. Returns ``None`` on
    malformed input so resolvers can short-circuit cleanly without
    raising on adversarial data."""
    try:
        a, b = value.split(":", 1)
        sysid, compid = int(a), int(b)
    except (ValueError, AttributeError):
        return None
    if not (0 <= sysid <= 255 and 0 <= compid <= 255):
        return None
    return sysid, compid


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
class VehicleRef:
    """Identifying details for the vehicle that emitted an autonomy
    event. All fields best-effort — set what the parser observes.

    MAVLink populates ``sysid`` / ``compid`` from the packet header;
    ``vehicle_id`` is the operator-configured opaque ID (mapped via
    fleet manifest); ``mission_id`` and ``frame`` come from
    higher-level message decoding when available.
    """

    sysid: int | None = None         # MAVLink system ID, 0..255
    compid: int | None = None        # MAVLink component ID, 0..255
    vehicle_id: str | None = None    # opaque fleet-configured identifier
    mission_id: str | None = None    # active mission, when known
    frame: str | None = None         # "GLOBAL", "LOCAL_NED", ...


@dataclass(frozen=True, slots=True)
class PrincipalHint:
    """How the parser thinks this event should bind to a KYA principal.

    The bridge applies a configurable strategy chain over these hints;
    multiple hints of different kinds may be present on one event.

    ``value`` shape per kind:
        container_label  -> the label *value* (e.g. ``"agent_42"``)
        service_account  -> ``"<namespace>/<sa_name>"``
        spiffe_id        -> the SPIFFE URI (covers x509 SVID and
                            MAVLink 2.0 signed-packet key_ids encoded
                            as ``spiffe://...``)
        process_user     -> the username
        vehicle_id       -> the opaque vehicle identifier
        mavlink_sysid    -> ``encode_mavlink_sysid(sysid, compid)``
        explicit         -> the KYA principal_id directly
        unknown          -> empty string (kept to keep the hint typed)
    """

    kind: PrincipalHintKind
    value: str


# ── BoundEvent Protocol ────────────────────────────────────────────


@runtime_checkable
class BoundEvent(Protocol):
    """Structural contract every event flowing through the bridge
    must satisfy.

    Both :class:`RuntimeEvent` and :class:`AutonomyEvent` satisfy this
    protocol today. Future families (industrial, network, ...) plug
    in by satisfying the same surface — no inheritance required.

    Performance note
    ----------------
    ``runtime_checkable`` walks ``__annotations__`` and is roughly 50×
    slower than concrete isinstance. The bridge does NOT call
    ``isinstance(ev, BoundEvent)`` in the per-event hot path; the
    protocol is used at API boundaries (function signatures, type
    checking) and in tests.

    Why no ``process`` here
    -----------------------
    Seven of the eight runtime-security parsers populate
    :class:`ProcessRef`, but autonomy events have :class:`VehicleRef`
    instead. Forcing every future event to carry an irrelevant
    ``process`` field would be protocol bloat. The bridge branches on
    event kind (``source_kind_of(ev.source_tool)``) where it needs
    family-specific context.
    """

    source_tool: SourceTool
    source_rule_id: str
    occurred_at_ts: float
    severity: RuntimeSeverity
    action: str
    message: str
    principal_hints: Sequence[PrincipalHint]
    tenant_id: str | None
    principal_id: str | None
    tags: Sequence[str]
    raw: dict[str, Any]


# ── Runtime-security canonical event ──────────────────────────────


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
                       from a documented vocabulary; unknown verbs
                       are allowed but won't match shipped
                       attack-chain rules.
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
            MITRE technique IDs, vendor tags
            (``mitre_persistence``, ``defense_evasion``, ...).
            Surfaced through to evidence metadata.
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


# ── Autonomy canonical event ──────────────────────────────────────


@dataclass(frozen=True, slots=True)
class AutonomyEvent:
    """One autonomous-system event, normalised across UAS / robotics
    protocols.

    Required fields mirror :class:`RuntimeEvent` so a single bridge
    can route both. Optional fields carry autonomy-specific context
    (vehicle, geo, mission, comms link) instead of container
    metadata.

    Identity caveat
    ---------------
    Bare MAVLink fields (``sysid`` / ``compid``) are forgeable bytes
    on the wire. Identity binding from these is **best-effort
    attribution**, not cryptographic identity. MAVLink 2.0 signed
    packets land in ``raw["mavlink_signature"]`` with the key_id
    surfaced as ``PrincipalHint(kind="explicit", value=<key_id>)`` or
    ``spiffe_id`` when SPIFFE infrastructure is configured.
    """

    source_tool: AutonomyTool
    source_rule_id: str
    occurred_at_ts: float
    severity: RuntimeSeverity
    action: str
    message: str

    vehicle: VehicleRef | None = None

    geo_lat: float | None = None     # degrees, WGS84
    geo_lon: float | None = None
    geo_alt_m: float | None = None

    flight_mode: str | None = None   # cross-version stable canonical mode name
    link_quality: int | None = None  # 0..100 percentage when telemetry provides it

    command_origin_addr: str | None = None  # e.g. "udp://10.0.0.5:14550"

    principal_hints: tuple[PrincipalHint, ...] = field(default_factory=tuple)

    tenant_id: str | None = None
    principal_id: str | None = None

    tags: tuple[str, ...] = field(default_factory=tuple)

    raw: dict[str, Any] = field(default_factory=dict)
