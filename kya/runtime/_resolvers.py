"""Default principal-resolver chain shipped with kya.runtime.

Goal: ``pip install veldt-kya`` -> Falco/Tetragon/etc. alerts bind to
KYA principals automatically, without the caller writing any glue
code.

The chain runs each strategy in order, stopping at the first hit.
Every strategy is OPTIONAL and lazy-imported so the default install
has zero new hard dependencies. A strategy that can't run (Docker
socket missing, k8s client not installed, no naming convention
matches) is silently skipped; the next strategy gets a chance.

Strategies, top to bottom of priority
-------------------------------------
1. **ExplicitBindingCache** -- pre-registered ``container_id ->
   (tenant_id, principal_id)`` mappings. Populated by SDK callers
   when they spawn a container they want bound. Strongest binding;
   no I/O.

2. **DockerLabelResolver** -- looks up the container by id via the
   Docker SDK and reads two labels: ``io.veldt.principal_id`` (or
   custom key) for principal, ``io.veldt.tenant_id`` for tenant.
   Cached per container_id for 60s. Skipped if the ``docker``
   package isn't installed or the daemon socket isn't reachable.

3. **K8sAnnotationResolver** -- placeholder for the equivalent
   strategy using k8s pod annotations. Stubbed in v1 (returns None);
   the polished implementation ships in the premium parser bundle
   with an informer cache.

4. **ContainerNameConventionResolver** -- if the container name
   matches a configurable regex (default: ``^agent[-_](?P<pid>...)$``),
   extract the principal_id from the named group. Cheapest possible
   binding for users following a naming convention.

5. **ProcessUserResolver** -- last-resort weak binding from a
   pre-configured ``{process_user: (tenant_id, principal_id)}`` map.
   Off by default; opt in by passing a non-empty map at chain
   construction.

If every strategy returns None, the bridge leaves the event
``unbound``. The event still flows through evidence-chain attach
(when an invocation_id was supplied) and attack-chain dispatch -- we
never silently drop runtime evidence.

Resolver contract
-----------------
A resolver is any callable taking a :class:`BoundEvent` (so it works
for both :class:`RuntimeEvent` and :class:`AutonomyEvent`) and
returning ``(tenant_id, principal_id, binding_method_label) | None``.
The chain treats them as opaque; new strategies (custom DBs, service
discovery, ...) can be added by callers via
:func:`build_default_resolver_chain` without modifying this module.
"""
from __future__ import annotations

import logging
import os
import re
import threading
import time
from collections import OrderedDict
from collections.abc import Callable

from ._canonical import BoundEvent, decode_mavlink_sysid

logger = logging.getLogger(__name__)


#: Resolver signature: takes any event satisfying :class:`BoundEvent`,
#: returns ``(tid, pid, method)`` or ``None``. The method label is
#: free-text and shows up in
#: ``RuntimeIngestResult.principal_binding_method`` so operators can
#: tell which strategy bound the event.
#:
#: Container-oriented resolvers self-gate via ``getattr(ev,
#: "container_id", None)`` so they cost roughly one attribute lookup
#: when an autonomy event flows through. The chain runs every
#: resolver per event; gating MUST be cheap.
Resolver = Callable[[BoundEvent], "tuple[str, str, str] | None"]


# ── Strategy 1: explicit binding cache ─────────────────────────────


class ExplicitBindingCache:
    """In-memory ``container_id -> (tenant_id, principal_id)`` cache.

    Process-local; LRU-bounded so a long-running collector never
    blows up. Thread-safe (the bridge may be driven from multiple
    threads in production -- one per inbound stream).

    Use ``kya.runtime.bind_container(...)`` to register; that's the
    public entrypoint. The class is module-global so all resolver
    chain instances see the same mappings.
    """

    _cache: OrderedDict[str, tuple[str, str]] = OrderedDict()
    _lock = threading.Lock()
    _max_entries = 10_000

    @classmethod
    def bind(
        cls, container_id: str, tenant_id: str, principal_id: str,
    ) -> None:
        """Register (or overwrite) a binding. Idempotent."""
        if not container_id or not tenant_id or not principal_id:
            return
        with cls._lock:
            cls._cache[container_id] = (tenant_id, principal_id)
            cls._cache.move_to_end(container_id)
            while len(cls._cache) > cls._max_entries:
                cls._cache.popitem(last=False)

    @classmethod
    def unbind(cls, container_id: str) -> None:
        """Remove a binding. Idempotent (no-op if not present)."""
        if not container_id:
            return
        with cls._lock:
            cls._cache.pop(container_id, None)

    @classmethod
    def clear(cls) -> None:
        """Drop ALL bindings. Test-only; never call from app code."""
        with cls._lock:
            cls._cache.clear()

    @classmethod
    def size(cls) -> int:
        with cls._lock:
            return len(cls._cache)

    def __call__(
        self, ev: BoundEvent,
    ) -> tuple[str, str, str] | None:
        cid = getattr(ev, "container_id", None)
        if not cid:
            return None
        with self._lock:
            hit = self._cache.get(cid)
            if hit:
                # LRU touch so popular containers don't get evicted
                self._cache.move_to_end(cid)
        if hit:
            return (*hit, "explicit_cache")
        return None


# ── Strategy 2: Docker label inspect ───────────────────────────────


class DockerLabelResolver:
    """Look up container labels via the Docker SDK.

    Cached per ``container_id`` with a TTL because docker-inspect is
    a real RPC; high-volume Falco streams would otherwise hammer the
    daemon socket.

    Lazy imports ``docker``. If the package isn't installed, this
    resolver returns None on every call -- the chain skips to the
    next strategy without raising. Users who want the resolver active
    install ``pip install veldt-kya[runtime-docker]``.
    """

    def __init__(
        self,
        *,
        principal_label: str = "io.veldt.principal_id",
        tenant_label: str = "io.veldt.tenant_id",
        default_tenant: str | None = None,
        cache_ttl_seconds: float = 60.0,
    ) -> None:
        self.principal_label = principal_label
        self.tenant_label = tenant_label
        self.default_tenant = default_tenant or os.environ.get(
            "KYA_RUNTIME_DEFAULT_TENANT")
        self.cache_ttl = float(cache_ttl_seconds)
        # cache: container_id -> (expires_at, (tid, pid) | None)
        self._cache: dict[
            str, tuple[float, tuple[str, str] | None]] = {}
        self._client_ready: bool | None = None
        self._client = None
        self._lock = threading.Lock()

    def _get_client(self):
        if self._client_ready is False:
            return None
        if self._client is not None:
            return self._client
        try:
            import docker  # noqa: PLC0415
        except ImportError:
            self._client_ready = False
            return None
        try:
            self._client = docker.from_env()
            self._client_ready = True
            return self._client
        except Exception:  # noqa: BLE001
            # Docker socket unreachable (no daemon, no permission, ...);
            # mark the resolver inert so we don't retry on every event.
            logger.debug(
                "[KYA-RESOLVER-DOCKER] from_env() failed; "
                "marking resolver inert.", exc_info=True,
            )
            self._client_ready = False
            return None

    def _lookup(self, container_id: str) -> tuple[str, str] | None:
        client = self._get_client()
        if client is None:
            return None
        try:
            container = client.containers.get(container_id)
        except Exception:  # noqa: BLE001
            # Container exited / not found / API error.
            return None
        labels = getattr(container, "labels", None) or {}
        principal = labels.get(self.principal_label)
        tenant = labels.get(self.tenant_label) or self.default_tenant
        if not principal or not tenant:
            return None
        return (str(tenant), str(principal))

    def __call__(
        self, ev: BoundEvent,
    ) -> tuple[str, str, str] | None:
        cid = getattr(ev, "container_id", None)
        if not cid:
            return None
        now = time.time()
        with self._lock:
            cached = self._cache.get(cid)
            if cached and cached[0] > now:
                result = cached[1]
            else:
                result = self._lookup(cid)
                self._cache[cid] = (now + self.cache_ttl, result)
        if result:
            return (*result, "docker_label")
        return None


# ── Strategy 3: k8s annotation (stub in OSS) ───────────────────────


class K8sAnnotationResolver:
    """Stub for the k8s annotation-based resolver.

    The polished version (informer + cached pod-> principal map)
    ships in the premium parser bundle. The open chain keeps a stub
    here so the chain order in customer code stays the same when
    they upgrade. Returns None for now.
    """

    def __call__(
        self, ev: BoundEvent,
    ) -> tuple[str, str, str] | None:
        return None


# ── Strategy 4: container-name naming convention ───────────────────


class ContainerNameConventionResolver:
    """Derive ``principal_id`` from ``container.name`` via regex.

    Default pattern: ``^agent[-_](?P<pid>[a-zA-Z0-9_]+)$``. Override
    by passing ``pattern=`` or setting
    ``KYA_RUNTIME_CONTAINER_NAME_PATTERN``. The pattern MUST contain
    a named group ``pid`` -- without it the resolver returns None.

    Tenant comes from ``default_tenant`` (constructor arg or
    ``KYA_RUNTIME_DEFAULT_TENANT`` env). With no default tenant the
    resolver returns None (we never invent a tenant -- evidence rows
    are tenant-scoped and getting that wrong is unsafe).
    """

    # Accepts both ``agent-foo-42`` and ``agent_foo_42`` since both
    # are common -- k8s pod names use dashes, ad-hoc docker names
    # often use underscores.
    DEFAULT_PATTERN = r"^agent[-_](?P<pid>[a-zA-Z0-9_\-]+)$"

    def __init__(
        self,
        *,
        pattern: str | None = None,
        default_tenant: str | None = None,
    ) -> None:
        pat = (
            pattern
            or os.environ.get("KYA_RUNTIME_CONTAINER_NAME_PATTERN")
            or self.DEFAULT_PATTERN
        )
        try:
            self.regex = re.compile(pat)
        except re.error as exc:
            logger.warning(
                "[KYA-RESOLVER-NAMECONV] invalid pattern %r: %s -- "
                "resolver will be inert.", pat, exc,
            )
            self.regex = None
        self.default_tenant = default_tenant or os.environ.get(
            "KYA_RUNTIME_DEFAULT_TENANT")

    def _container_name(self, ev: BoundEvent) -> str | None:
        # Raw output_fields["container.name"] is the canonical source
        # for Falco; Tetragon parsers will land it the same place.
        of = ev.raw.get("output_fields") if isinstance(
            ev.raw, dict) else None
        if isinstance(of, dict):
            name = of.get("container.name")
            if isinstance(name, str) and name.strip():
                return name.strip()
        return None

    def __call__(
        self, ev: BoundEvent,
    ) -> tuple[str, str, str] | None:
        if self.regex is None or not self.default_tenant:
            return None
        # Gate: only events that carry a container_id field at all
        # can possibly match a container-name regex. Skips the regex
        # work on autonomy events at minimal cost (one getattr).
        if getattr(ev, "container_id", None) is None:
            return None
        name = self._container_name(ev)
        if not name:
            return None
        m = self.regex.match(name)
        if not m:
            return None
        try:
            pid = m.group("pid")
        except IndexError:
            return None
        if not pid:
            return None
        return (self.default_tenant, pid, "container_name")


# ── Strategy 5: process-user map ───────────────────────────────────


class ProcessUserResolver:
    """Bind based on the process user reported by the runtime tool.

    Last-resort: process-user identity is weak -- many distinct
    containers share ``root`` -- so this only binds when the operator
    pre-configures a map. Empty map (the default) = resolver inert.

    Map shape: ``{user_name: (tenant_id, principal_id)}``.
    """

    def __init__(
        self,
        user_map: dict[str, tuple[str, str]] | None = None,
    ) -> None:
        self.user_map = dict(user_map or {})

    def __call__(
        self, ev: BoundEvent,
    ) -> tuple[str, str, str] | None:
        if not self.user_map:
            return None
        process = getattr(ev, "process", None)
        if process is None:
            return None
        user = process.user
        if not user:
            return None
        hit = self.user_map.get(user)
        if not hit:
            return None
        return (*hit, "process_user_map")


# ── Strategy 6: MAVLink (sysid, compid) -> principal ────────────────


class MavlinkSysidResolver:
    """Resolve a ``mavlink_sysid`` hint to a principal_id via a
    fleet manifest.

    The manifest maps each known ``(sysid, compid)`` pair to a
    ``(tenant_id, principal_id)``. Unmapped pairs return None and the
    chain continues — an unmapped vehicle is treated as an
    unauthorized command source, which is the whole point: the
    bridge surfaces a principal-inconsistency signal rather than
    inventing identity.

    The resolver is NOT in the default chain because every fleet's
    manifest is bespoke. Callers wire it in explicitly via
    :func:`build_resolver_chain_with_mavlink`.

    Identity caveat
    ---------------
    MAVLink sysid/compid bytes are forgeable on the wire. This
    resolver provides **best-effort attribution**, not cryptographic
    identity. For signed packets (MAVLink 2.0 + signing), the parser
    surfaces the key_id as an ``explicit`` or ``spiffe_id`` hint that
    takes priority over the sysid resolver in the default chain.
    """

    def __init__(
        self,
        fleet_manifest: dict[tuple[int, int], tuple[str, str]],
    ) -> None:
        self._manifest = dict(fleet_manifest)

    def __call__(
        self, ev: BoundEvent,
    ) -> tuple[str, str, str] | None:
        # Gate: only MAVLink events carry meaningful sysid hints.
        # A runtime-security event that happens to ship a
        # mavlink_sysid hint (test fixtures, copy-paste bugs) must
        # not bind via this resolver -- the principal it would
        # resolve to is unrelated to the actual container actor.
        if ev.source_tool != "mavlink":
            return None
        for hint in ev.principal_hints:
            if hint.kind != "mavlink_sysid":
                continue
            decoded = decode_mavlink_sysid(hint.value)
            if decoded is None:
                continue
            hit = self._manifest.get(decoded)
            if hit:
                return (*hit, "mavlink_sysid")
        return None


# ── Chain runner ───────────────────────────────────────────────────


class PrincipalResolverChain:
    """Run a list of resolvers in order; stop at the first hit.

    A resolver that raises is logged + skipped; one buggy strategy
    cannot block the rest of the chain. Order is significant:
    strongest / cheapest first.
    """

    def __init__(self, resolvers: list[Resolver]) -> None:
        self.resolvers = list(resolvers)

    def __call__(
        self, ev: BoundEvent,
    ) -> tuple[str, str, str] | None:
        for r in self.resolvers:
            try:
                result = r(ev)
            except Exception:  # noqa: BLE001
                logger.exception(
                    "[KYA-RESOLVER-CHAIN] resolver %s raised", type(r).__name__,
                )
                continue
            if result:
                return result
        return None


# ── Factory ────────────────────────────────────────────────────────


def build_default_resolver_chain(
    *,
    default_tenant: str | None = None,
    container_name_pattern: str | None = None,
    docker_principal_label: str = "io.veldt.principal_id",
    docker_tenant_label: str = "io.veldt.tenant_id",
    process_user_map: dict[str, tuple[str, str]] | None = None,
    mavlink_fleet_manifest: (
        dict[tuple[int, int], tuple[str, str]] | None
    ) = None,
) -> PrincipalResolverChain:
    """Construct the default chain.

    Order: explicit cache -> docker label -> k8s annotation (stub) ->
    name convention -> process-user map -> (mavlink sysid, if a
    fleet manifest was supplied).

    All args are optional; sensible defaults pulled from env where
    helpful. Pass ``default_tenant=`` to make the naming-convention
    resolver active without an env var. Pass ``mavlink_fleet_manifest``
    to bind MAVLink events to principals; without it, the MAVLink
    resolver is omitted (and unmapped vehicles surface as unbound,
    which is correct — unknown vehicles are unauthorized command
    sources, not implicit principals).
    """
    resolvers: list[Resolver] = [
        ExplicitBindingCache(),
        DockerLabelResolver(
            principal_label=docker_principal_label,
            tenant_label=docker_tenant_label,
            default_tenant=default_tenant,
        ),
        K8sAnnotationResolver(),
        ContainerNameConventionResolver(
            pattern=container_name_pattern,
            default_tenant=default_tenant,
        ),
        ProcessUserResolver(user_map=process_user_map),
    ]
    if mavlink_fleet_manifest:
        resolvers.append(MavlinkSysidResolver(mavlink_fleet_manifest))
    return PrincipalResolverChain(resolvers)


# ── Public SDK convenience ─────────────────────────────────────────


def bind_container(
    container_id: str, tenant_id: str, principal_id: str,
) -> None:
    """Register a container_id -> (tenant, principal) binding so any
    subsequent runtime alert on that container auto-binds. Idempotent.

    Designed to be called by agent code at container-spawn time:

    .. code-block:: python

        cont = docker_client.containers.run(image, ...)
        kya.runtime.bind_container(
            cont.id, tenant_id="acme", principal_id="agent_research_42",
        )
        # ... Falco alerts on cont.id now auto-bind to agent_research_42
    """
    ExplicitBindingCache.bind(container_id, tenant_id, principal_id)


def unbind_container(container_id: str) -> None:
    """Remove an explicit container binding. Call when the container
    exits to bound the cache; not strictly required -- the cache is
    LRU."""
    ExplicitBindingCache.unbind(container_id)
