"""
KYA Runtime Security Bridge.

Ingests runtime-security events from any of the major OSS sources
(Falco, Tetragon, Tracee, Sysdig OSS, osquery, auditd, k8s audit logs,
custom eBPF probes) through ONE canonical interface, binds each event
to a KYA principal, attaches it to the evidence chain, and feeds it to
the attack-chain engine for cross-layer correlation with agent
behavior.

Positioning
-----------
KYA does NOT replace Falco/Tetragon/etc. It turns their alerts into
**principal-bound evidence** that correlates with agent tool calls.
Examples of patterns this unlocks that single-tool detection cannot:

* Agent A calls sandbox tool, Falco detects a shell escape in the
  same container within 60 s -> high-confidence incident.
* Agent claims it ran `db.query`, but Tetragon observed an outbound
  curl to a non-corporate host -> claim/observation divergence.
* Service account S issued a k8s API call, k8s-audit recorded it, but
  S has no recent legitimate evidence chain -> orphan signal.

Architecture
------------
::

    raw JSON / NDJSON / unix socket
              |
              v
    kya.runtime.parsers.<tool>.parse(raw_dict) -> RuntimeEvent
              |
              v
    kya.runtime.record_runtime_event(ev)
       |    |    |
       |    |    +-> kya.attack_chains.process_evidence(...)
       |    +------> kya.record_evidence(...)        (HMAC chain attach)
       +-----------> principal-binding (label / SA / SPIFFE / proc tree)

Design contract
---------------
- **Modular**: each parser is its own module with no cross-parser
  imports. A Falco user does not pay for Tetragon code.
- **Self-contained**: parsers depend only on stdlib + canonical types.
- **DRY**: principal-binding, evidence-attach, attack-chain dispatch
  are written ONCE in the bridge.
- **Extensible**: add tool #9 = one new parser module + one
  registration line.
- **Optional everywhere**: importing ``kya.runtime`` pulls no runtime-
  security tool dep. Each parser may have its own light extras
  (PyYAML for some, etc.) but the canonical interface stays free.
- **Fail-soft**: a parser that can't handle a payload returns
  ``None``; the bridge logs and drops, never raises into the caller.

Public surface
--------------
Canonical types (``_canonical.py``)
    RuntimeEvent, ProcessRef, PrincipalHint, RuntimeSeverity, SourceTool

Bridge (``_bridge.py``)
    record_runtime_event(canonical) -> RuntimeIngestResult
    ingest(source_tool, raw, *, db=None) -> RuntimeIngestResult

Registry (``_registry.py``)
    register_parser(name, parser)
    get_parser(name) -> Parser | None
    list_parsers() -> tuple[str, ...]

Parser protocol (``parsers/_protocol.py``)
    Parser.parse(raw: dict) -> RuntimeEvent | None
    Parser.can_parse(raw: dict) -> bool

First shipped parser
--------------------
* ``parsers.falco`` -- Falco (CNCF runtime security)
"""
from __future__ import annotations

# Auto-register the parsers that ship with KYA. New parsers added in
# `parsers/__init__.py` get picked up here without touching this file.
from . import parsers as _bundled_parsers  # noqa: F401 (registration side-effect)
from ._bridge import (
    RuntimeIngestResult,
    ingest,
    record_runtime_event,
    reset_principal_resolver_to_default,
    set_principal_resolver,
)
from ._canonical import (
    AutonomyEvent,
    AutonomyTool,
    BoundEvent,
    PrincipalHint,
    PrincipalHintKind,
    ProcessRef,
    RuntimeEvent,
    RuntimeSecurityTool,
    RuntimeSeverity,
    SourceKind,
    SourceTool,
    VehicleRef,
    decode_mavlink_sysid,
    encode_mavlink_sysid,
    source_kind_of,
)
from ._registry import (
    RuntimeParserError,
    get_parser,
    list_parsers,
    register_parser,
)
from ._resolvers import (
    ContainerNameConventionResolver,
    DockerLabelResolver,
    ExplicitBindingCache,
    K8sAnnotationResolver,
    MavlinkSysidResolver,
    PrincipalResolverChain,
    ProcessUserResolver,
    Resolver,
    bind_container,
    build_default_resolver_chain,
    unbind_container,
)

__all__ = [
    # Canonical types
    "BoundEvent",
    "RuntimeEvent",
    "AutonomyEvent",
    "ProcessRef",
    "VehicleRef",
    "PrincipalHint",
    "PrincipalHintKind",
    "RuntimeSeverity",
    "SourceTool",
    "SourceKind",
    "RuntimeSecurityTool",
    "AutonomyTool",
    "source_kind_of",
    "encode_mavlink_sysid",
    "decode_mavlink_sysid",
    # Bridge
    "record_runtime_event",
    "ingest",
    "RuntimeIngestResult",
    "set_principal_resolver",
    "reset_principal_resolver_to_default",
    # Registry
    "register_parser",
    "get_parser",
    "list_parsers",
    "RuntimeParserError",
    # Auto-resolver chain
    "Resolver",
    "PrincipalResolverChain",
    "build_default_resolver_chain",
    "ExplicitBindingCache",
    "DockerLabelResolver",
    "K8sAnnotationResolver",
    "ContainerNameConventionResolver",
    "ProcessUserResolver",
    "MavlinkSysidResolver",
    "bind_container",
    "unbind_container",
]
