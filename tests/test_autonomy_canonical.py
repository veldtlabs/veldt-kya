"""Tests for the autonomy-side canonical event model + bridge routing.

Covers:
* :class:`BoundEvent` Protocol shape — RuntimeEvent and AutonomyEvent
  both satisfy it.
* :func:`source_kind_of` classification.
* :func:`encode_mavlink_sysid` / :func:`decode_mavlink_sysid` round-trip.
* Bridge routes an AutonomyEvent through to an autonomy-flavoured
  payload + evidence_kind.
* :class:`MavlinkSysidResolver` resolves a fleet manifest to a
  principal_id; the existing container-only resolvers no-op on
  autonomy events.
"""
from __future__ import annotations

import time

import pytest

from kya.runtime import (
    AutonomyEvent,
    BoundEvent,
    ContainerNameConventionResolver,
    DockerLabelResolver,
    ExplicitBindingCache,
    MavlinkSysidResolver,
    PrincipalHint,
    ProcessRef,
    PrincipalResolverChain,
    RuntimeEvent,
    VehicleRef,
    decode_mavlink_sysid,
    encode_mavlink_sysid,
    record_runtime_event,
    set_principal_resolver,
    source_kind_of,
)


# ── Encoding helpers ──────────────────────────────────────────────


class TestSysidEncoding:
    def test_round_trip(self):
        for sysid, compid in [(1, 1), (255, 0), (0, 255), (10, 191)]:
            encoded = encode_mavlink_sysid(sysid, compid)
            assert decode_mavlink_sysid(encoded) == (sysid, compid)

    def test_decode_rejects_garbage(self):
        for bad in ["", "abc", "1", "1:", ":2", "1:2:3", "300:1", "-1:0", None]:
            assert decode_mavlink_sysid(bad) is None  # type: ignore[arg-type]

    def test_encode_validates_range(self):
        with pytest.raises(ValueError):
            encode_mavlink_sysid(256, 0)
        with pytest.raises(ValueError):
            encode_mavlink_sysid(0, -1)


# ── source_kind_of ────────────────────────────────────────────────


class TestSourceKind:
    @pytest.mark.parametrize("tool", [
        "falco", "tetragon", "tracee", "sysdig",
        "osquery", "auditd", "k8s_audit", "ebpf",
    ])
    def test_runtime_security_tools(self, tool):
        assert source_kind_of(tool) == "runtime_security"

    def test_mavlink_is_autonomy(self):
        assert source_kind_of("mavlink") == "autonomy"


# ── BoundEvent Protocol ───────────────────────────────────────────


class TestBoundEventProtocol:
    """RuntimeEvent and AutonomyEvent must both structurally satisfy
    :class:`BoundEvent`. This is the contract the bridge depends on."""

    def test_runtime_event_satisfies(self):
        ev = RuntimeEvent(
            source_tool="falco",
            source_rule_id="r1",
            occurred_at_ts=time.time(),
            severity="high",
            action="x",
            message="m",
        )
        assert isinstance(ev, BoundEvent)

    def test_autonomy_event_satisfies(self):
        ev = AutonomyEvent(
            source_tool="mavlink",
            source_rule_id="command/arm",
            occurred_at_ts=time.time(),
            severity="medium",
            action="arm",
            message="ARM requested",
        )
        assert isinstance(ev, BoundEvent)

    def test_required_attributes(self):
        ev = AutonomyEvent(
            source_tool="mavlink",
            source_rule_id="r",
            occurred_at_ts=1.0,
            severity="low",
            action="x",
            message="m",
        )
        for attr in (
            "source_tool", "source_rule_id", "occurred_at_ts",
            "severity", "action", "message",
            "principal_hints", "tenant_id", "principal_id",
            "tags", "raw",
        ):
            assert hasattr(ev, attr), f"AutonomyEvent missing {attr}"


# ── Bridge routes both event families ─────────────────────────────


class TestBridgeRoutesBoth:
    def setup_method(self):
        # No resolver so the bridge stays deterministic; the test
        # passes pre-bound events.
        set_principal_resolver(None)

    def teardown_method(self):
        # Restore default resolver chain for downstream tests.
        from kya.runtime import reset_principal_resolver_to_default
        reset_principal_resolver_to_default()

    def test_runtime_security_event_classified(self):
        ev = RuntimeEvent(
            source_tool="falco",
            source_rule_id="r",
            occurred_at_ts=time.time(),
            severity="high",
            action="shell_in_container",
            message="m",
            tenant_id="t",
            principal_id="p",
        )
        result = record_runtime_event(ev)
        assert result.accepted is True
        assert result.source_kind == "runtime_security"
        assert result.source_tool == "falco"

    def test_autonomy_event_classified(self):
        ev = AutonomyEvent(
            source_tool="mavlink",
            source_rule_id="command/arm",
            occurred_at_ts=time.time(),
            severity="medium",
            action="arm",
            message="ARM requested",
            vehicle=VehicleRef(sysid=2, compid=1, vehicle_id="uav_002"),
            tenant_id="t",
            principal_id="uav_002",
        )
        result = record_runtime_event(ev)
        assert result.accepted is True
        assert result.source_kind == "autonomy"
        assert result.source_tool == "mavlink"


# ── Resolver gating ───────────────────────────────────────────────


class TestResolverGating:
    """Container-oriented resolvers must no-op on autonomy events.
    Otherwise they'd try ``ev.container_id`` and crash at 50 Hz."""

    def _autonomy_ev(self):
        return AutonomyEvent(
            source_tool="mavlink",
            source_rule_id="r",
            occurred_at_ts=1.0,
            severity="low",
            action="x",
            message="m",
            vehicle=VehicleRef(sysid=2, compid=1),
        )

    def test_explicit_binding_cache_skips_autonomy(self):
        assert ExplicitBindingCache()(self._autonomy_ev()) is None

    def test_docker_label_resolver_skips_autonomy(self):
        assert DockerLabelResolver()(self._autonomy_ev()) is None

    def test_container_name_resolver_skips_autonomy(self):
        r = ContainerNameConventionResolver(default_tenant="t")
        assert r(self._autonomy_ev()) is None


# ── MavlinkSysidResolver ──────────────────────────────────────────


class TestMavlinkSysidResolver:
    FLEET = {(1, 1): ("acme", "uav_001"), (2, 1): ("acme", "uav_002")}

    def _ev_with_sysid_hint(self, sysid: int, compid: int) -> AutonomyEvent:
        return AutonomyEvent(
            source_tool="mavlink",
            source_rule_id="r",
            occurred_at_ts=1.0,
            severity="low",
            action="x",
            message="m",
            principal_hints=(
                PrincipalHint(
                    kind="mavlink_sysid",
                    value=encode_mavlink_sysid(sysid, compid),
                ),
            ),
        )

    def test_resolves_known_sysid(self):
        r = MavlinkSysidResolver(self.FLEET)
        assert r(self._ev_with_sysid_hint(1, 1)) == ("acme", "uav_001", "mavlink_sysid")

    def test_unknown_sysid_returns_none(self):
        # Unknown vehicle = unauthorized command source; resolver
        # surfaces it as unbound rather than inventing a principal.
        r = MavlinkSysidResolver(self.FLEET)
        assert r(self._ev_with_sysid_hint(99, 0)) is None

    def test_malformed_hint_value_returns_none(self):
        r = MavlinkSysidResolver(self.FLEET)
        ev = AutonomyEvent(
            source_tool="mavlink",
            source_rule_id="r",
            occurred_at_ts=1.0,
            severity="low",
            action="x",
            message="m",
            principal_hints=(
                PrincipalHint(kind="mavlink_sysid", value="garbage"),
            ),
        )
        assert r(ev) is None

    def test_ignores_non_mavlink_hints(self):
        r = MavlinkSysidResolver(self.FLEET)
        ev = AutonomyEvent(
            source_tool="mavlink",
            source_rule_id="r",
            occurred_at_ts=1.0,
            severity="low",
            action="x",
            message="m",
            principal_hints=(
                PrincipalHint(kind="container_label", value="not_here"),
            ),
        )
        assert r(ev) is None

    def test_chain_with_mavlink_resolver(self):
        chain = PrincipalResolverChain([
            ExplicitBindingCache(),
            DockerLabelResolver(),
            MavlinkSysidResolver(self.FLEET),
        ])
        # Autonomy event flows past the container resolvers and
        # binds via the MAVLink one.
        ev = self._ev_with_sysid_hint(2, 1)
        assert chain(ev) == ("acme", "uav_002", "mavlink_sysid")

    def test_does_not_bind_runtime_security_event(self):
        """A Falco event that happens to carry a mavlink_sysid hint
        (test-fixture mix-up, copy-paste bug) MUST NOT bind via the
        MAVLink resolver -- the principal would be unrelated to the
        actual container actor."""
        r = MavlinkSysidResolver(self.FLEET)
        ev = RuntimeEvent(
            source_tool="falco",
            source_rule_id="r",
            occurred_at_ts=1.0,
            severity="low",
            action="x",
            message="m",
            principal_hints=(
                PrincipalHint(
                    kind="mavlink_sysid",
                    value=encode_mavlink_sysid(1, 1),
                ),
            ),
        )
        assert r(ev) is None


# ── Bridge fail-soft ─────────────────────────────────────────────


class TestBridgeFailSoft:
    """A parser that mis-classifies its event (RuntimeEvent with
    source_tool='mavlink', or vice versa) must NOT crash the bridge
    or silently emit a malformed payload."""

    def setup_method(self):
        set_principal_resolver(None)

    def teardown_method(self):
        from kya.runtime import reset_principal_resolver_to_default
        reset_principal_resolver_to_default()

    def test_misclassified_event_raises(self):
        """A parser that emits a RuntimeEvent shape but tags it with
        an autonomy source_tool violates the bridge's contract:
        class and source_tool family MUST agree, otherwise the
        signed evidence would record a wrong source_kind. The
        bridge raises ValueError rather than producing malformed
        evidence -- this is the audit-integrity guard."""
        import pytest as _pytest
        ev = RuntimeEvent(
            source_tool="mavlink",  # type: ignore[arg-type]
            source_rule_id="r",
            occurred_at_ts=1.0,
            severity="low",
            action="x",
            message="m",
            tenant_id="t",
            principal_id="p",
        )
        with _pytest.raises(ValueError, match="parser must align"):
            record_runtime_event(ev)

    def test_aligned_class_and_source_tool_routes_correctly(self):
        """Sanity check: the happy path -- AutonomyEvent with an
        autonomy source_tool -- produces an autonomy-flavoured
        payload and a correctly-tagged result."""
        ev = AutonomyEvent(
            source_tool="mavlink",
            source_rule_id="command/arm",
            occurred_at_ts=1.0,
            severity="low",
            action="arm",
            message="ARM",
            vehicle=VehicleRef(sysid=1, compid=1),
            tenant_id="t",
            principal_id="p",
        )
        result = record_runtime_event(ev)
        assert result.accepted is True
        assert result.source_kind == "autonomy"


# ── Backwards-compat: 8 existing parsers keep working ─────────────


class TestBackwardsCompat:
    """Existing RuntimeEvent producers must round-trip through the
    refactored bridge without code changes."""

    def test_runtime_event_unchanged_shape(self):
        # The dataclass fields are exactly as v0.1.7 — no field rename,
        # no new required arg. A pre-bound RuntimeEvent constructed the
        # old way still works.
        ev = RuntimeEvent(
            source_tool="tetragon",
            source_rule_id="policy_42",
            occurred_at_ts=time.time(),
            severity="critical",
            action="exec_from_writable_dir",
            message="suspect exec",
            container_id="c0ffee",
            process=ProcessRef(pid=42, name="bash"),
            tenant_id="acme",
            principal_id="agent_alice",
        )
        assert ev.container_id == "c0ffee"
        assert ev.process.pid == 42
        assert isinstance(ev, BoundEvent)
