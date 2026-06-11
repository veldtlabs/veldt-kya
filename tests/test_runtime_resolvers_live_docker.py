"""Live Docker test for the auto-resolver chain.

Goal: prove the "plug-and-play" claim end-to-end. We launch a REAL
labeled Docker container, construct a Falco-shape alert that names
it, run ``kya.runtime.ingest(...)`` with **zero config** (default
chain), and assert the bridge auto-bound the alert via the
``io.veldt.principal_id`` label.

Skipped when:
* ``docker`` SDK is not importable, OR
* the Docker daemon socket is not reachable.

Run manually on dev machines or in CI runners with Docker access.
"""
from __future__ import annotations

import uuid

import pytest

from kya.runtime import (
    DockerLabelResolver,
    ExplicitBindingCache,
    bind_container,
    ingest,
    reset_principal_resolver_to_default,
)
from kya.runtime._canonical import RuntimeEvent

docker = pytest.importorskip("docker")


@pytest.fixture(scope="module")
def docker_client():
    try:
        client = docker.from_env()
        client.ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Docker daemon not reachable: {exc}")
    return client


@pytest.fixture(autouse=True)
def _reset_state():
    ExplicitBindingCache.clear()
    reset_principal_resolver_to_default()
    yield
    ExplicitBindingCache.clear()
    reset_principal_resolver_to_default()


def _make_falco_alert(container_id: str, container_name: str) -> dict:
    """A minimal Falco-shape alert pointing at our test container.
    Mirrors the JSON Falco actually emits (verified by the live
    capture in ``tests/fixtures/falco_live/*.json``)."""
    return {
        "time": "2026-05-29T10:00:00.000Z",
        "rule": "Test rule",
        "priority": "Warning",
        "output": "test event for resolver",
        "tags": ["test"],
        "hostname": "test-host",
        "source": "syscall",
        "output_fields": {
            "container.id": container_id,
            "container.name": container_name,
            "evt.time": 1748513025000000000,
            "proc.cmdline": "x",
            "proc.name": "x",
            "proc.pid": 1,
            "user.name": "root",
            "user.uid": 0,
        },
    }


# ── Strategy 1: explicit cache via SDK call ──────────────────


def test_live_explicit_bind_container_makes_alert_auto_bind(docker_client):
    """The simplest plug-and-play story: agent code calls
    ``bind_container(...)`` when it spawns a container; subsequent
    Falco alerts on that container auto-bind. Zero Falco config, zero
    Docker label config."""
    container = docker_client.containers.run(
        "alpine:3.18",
        command=["sleep", "5"],
        detach=True,
        name=f"kya-test-explicit-{uuid.uuid4().hex[:8]}",
    )
    try:
        bind_container(
            container_id=container.id[:12],  # Falco emits 12-char short id
            tenant_id="t_live",
            principal_id="agent_under_test",
        )
        alert = _make_falco_alert(
            container_id=container.id[:12],
            container_name=container.name,
        )
        r = ingest(alert)
        assert r.accepted is True
        assert r.tenant_id == "t_live"
        assert r.principal_id == "agent_under_test"
        assert r.principal_binding_method == "explicit_cache"
    finally:
        container.stop(timeout=1)
        container.remove(force=True)


# ── Strategy 2: Docker label inspect ────────────────────────


def test_live_docker_label_resolver_auto_binds_labeled_container(
    docker_client,
):
    """The other zero-glue path: customer labels their container with
    ``io.veldt.principal_id`` (and optionally ``io.veldt.tenant_id``);
    KYA's bridge inspects the container via the Docker SDK and binds
    automatically -- the customer never had to call any KYA API."""
    container = docker_client.containers.run(
        "alpine:3.18",
        command=["sleep", "5"],
        detach=True,
        name=f"kya-test-label-{uuid.uuid4().hex[:8]}",
        labels={
            "io.veldt.principal_id": "agent_labeled_xyz",
            "io.veldt.tenant_id": "t_labeled",
        },
    )
    try:
        # Use the resolver in isolation (not the full chain) so we
        # are unambiguously testing Docker-label binding.
        resolver = DockerLabelResolver()
        alert = _make_falco_alert(
            container_id=container.id[:12],
            container_name=container.name,
        )
        # Bridge constructs the canonical event the parser would
        # produce, with the container_id populated -- that's what
        # the resolver inspects against.
        ev = RuntimeEvent(
            source_tool="falco",
            source_rule_id="r",
            occurred_at_ts=100.0,
            severity="medium",
            action="x",
            message="m",
            container_id=container.id[:12],
            raw=alert,
        )
        result = resolver(ev)
        assert result is not None, (
            "Docker label resolver should have bound the labeled "
            "container. Check daemon socket access.")
        tid, pid, method = result
        assert tid == "t_labeled"
        assert pid == "agent_labeled_xyz"
        assert method == "docker_label"
    finally:
        container.stop(timeout=1)
        container.remove(force=True)


def test_live_full_chain_binds_labeled_container_with_no_caller_glue(
    docker_client,
):
    """The full plug-and-play story end-to-end: spin a labeled
    container, hand a Falco JSON to ``ingest`` -- the default chain
    binds it without the caller writing ANY resolver or registration
    code."""
    container = docker_client.containers.run(
        "alpine:3.18",
        command=["sleep", "5"],
        detach=True,
        name=f"kya-test-fullchain-{uuid.uuid4().hex[:8]}",
        labels={
            "io.veldt.principal_id": "agent_chain_demo",
            "io.veldt.tenant_id": "t_chain",
        },
    )
    try:
        alert = _make_falco_alert(
            container_id=container.id[:12],
            container_name=container.name,
        )
        r = ingest(alert)  # zero glue, just the Falco JSON in
        assert r.accepted is True
        assert r.tenant_id == "t_chain"
        assert r.principal_id == "agent_chain_demo"
        # Default chain reports docker_label since explicit cache is
        # empty -- this is the binding strategy that fired.
        assert r.principal_binding_method == "docker_label"
    finally:
        container.stop(timeout=1)
        container.remove(force=True)


def test_live_chain_falls_through_to_unbound_when_nothing_matches(
    docker_client,
):
    """An unlabeled, never-registered container with a name that
    doesn't fit the naming convention must end up ``unbound`` -- and
    the bridge still accepts the event so evidence isn't lost.
    Proves the fail-soft contract on a real Docker container."""
    container = docker_client.containers.run(
        "alpine:3.18",
        command=["sleep", "5"],
        detach=True,
        # No labels, no agent_* name -> nothing should bind.
        name=f"kya-test-orphan-{uuid.uuid4().hex[:8]}",
    )
    try:
        alert = _make_falco_alert(
            container_id=container.id[:12],
            container_name=container.name,
        )
        r = ingest(alert)
        assert r.accepted is True
        assert r.principal_binding_method == "unbound"
        assert r.tenant_id is None
        assert r.principal_id is None
    finally:
        container.stop(timeout=1)
        container.remove(force=True)
