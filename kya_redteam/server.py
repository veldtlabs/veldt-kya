"""KYA Red-Team Sidecar — standalone FastAPI app.

Out-of-process runner for red-team campaigns. Lifts the long-running
multi-turn work out of vd-app's request workers so:
  - A 10-minute multi-turn campaign can't tie up a uvicorn worker
  - A crashing PyRIT call can't cascade into the main API
  - The sidecar scales independently (CPU + memory)
  - Concurrent run capacity grows by adding sidecar replicas, not by
    bloating vd-app

How it composes with the rest of the stack
------------------------------------------
  vd-app                         <--polls run row -- dashboard
    │ POST /v1/runs (bearer-auth)
    ▼
  vd-kya-redteam (this)
    │ run_campaign_async (in-process thread pool)
    │   ├── target.send(...)         ──> customer's agent endpoint
    │   ├── attacker_llm.call(...)   ──> Anthropic/OpenAI/Groq/...
    │   ├── record_finding(...)      ──> Postgres (shared with vd-app)
    │   ├── update_run_progress(...) ──> Postgres
    │   └── kya_poster.record_rogue(...) ──> vd-app /events/rogue
    ▼
  ... finally finalize_run on the kya_redteam_runs row

The dashboard never talks to the sidecar — it always reads the run
row via vd-app. This keeps the auth surface narrow (sidecar is
internal-only) and the dashboard logic identical between in-process
and sidecar deployments.

Auth
----
POST /v1/runs requires `Authorization: Bearer ${KYA_REDTEAM_SIDECAR_SECRET}`.
The secret is shared between vd-app and the sidecar via the .env file.
Cancel + healthz are public (cancel is idempotent + tenant-scoped via
the run_id, and healthz needs to be reachable by k8s/docker).
"""
from __future__ import annotations

import hmac
import logging
import os

try:
    from fastapi import Depends, FastAPI, Header, HTTPException
    from pydantic import BaseModel
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "kya_redteam.server requires `pip install fastapi uvicorn pydantic`"
    ) from exc


logging.basicConfig(
    # logging.basicConfig requires the level name in UPPERCASE; the env
    # var is conventionally lowercase ("info", "debug") so normalize.
    level=os.environ.get("KYA_REDTEAM_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("kya_redteam.server")


# ── Auth (constant-time bearer check, applied via Depends) ──────────

def require_sidecar_auth(authorization: str | None = Header(None)) -> None:
    """FastAPI dependency. Constant-time bearer comparison via
    hmac.compare_digest to defeat timing side-channels.

    Attached to every protected route via `dependencies=[Depends(...)]`
    on the FastAPI app at creation time, so a new endpoint can't
    accidentally ship unauthenticated.
    """
    expected = os.environ.get("KYA_REDTEAM_SIDECAR_SECRET", "").strip()
    if not expected:
        if os.environ.get("KYA_REDTEAM_SIDECAR_ALLOW_UNAUTH", "") != "1":
            raise HTTPException(
                503,
                "KYA_REDTEAM_SIDECAR_SECRET is not set on the sidecar; "
                "refusing requests. Set the env var or "
                "KYA_REDTEAM_SIDECAR_ALLOW_UNAUTH=1 for dev.",
            )
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authorization: Bearer <secret> required")
    presented = authorization.split(" ", 1)[1].strip()
    if not hmac.compare_digest(presented.encode(), expected.encode()):
        raise HTTPException(401, "invalid bearer token")


# ── Request / response models ───────────────────────────────────────

class RunRequest(BaseModel):
    """The campaign + target + run config that vd-app sends to the
    sidecar. All target authentication has already been resolved
    server-side (vd-app decrypted the secret); the sidecar receives a
    ready-to-use target_endpoint + token pair OR a materialized
    target_id that the sidecar re-materializes from the shared DB."""
    tenant_id: str
    initiated_by: str | None = None
    # Campaign dict (from kya_redteam_campaigns row)
    campaign: dict
    # Either: target_id (sidecar re-materializes from DB) OR ad-hoc fields
    target_id: int | None = None
    target_endpoint: str | None = None
    target_token: str | None = None
    target_body_template: dict | None = None
    target_timeout_s: float = 30.0
    target_rate_limit_rps: float = 0.0
    # Optional override
    dataset_override: list[dict] | None = None


# ── App ─────────────────────────────────────────────────────────────

def _warm_imports() -> dict:
    """Pre-import the heavy modules the endpoints need so the first
    request doesn't pay 100ms+ of SQLAlchemy engine + LiteLLM init
    cost. Also probes attacker-LLM reachability + target-vault key
    presence so operators see config gaps at boot instead of at first
    campaign run.

    Returns a status dict that /v1/config + /healthz surface.
    """
    status = {
        "db": False,
        "redteam_pkg": False,
        "errors": [],
        "warnings": [],
        # Filled by the LLM probe below
        "attacker_llm_standard_reachable": None,
        "attacker_llm_premium_reachable": None,
        "target_vault_key_configured": None,
    }
    try:
        import db.database  # type: ignore
        # Touch SessionLocal so the engine actually initializes
        _ = db.database.SessionLocal
        status["db"] = True
    except Exception as exc:
        status["errors"].append(f"db.database: {exc}")
        logger.warning("[REDTEAM-SIDECAR] warm import db.database: %s", exc)
    try:
        import kya_redteam  # noqa: F401
        from kya_redteam.pyrit_target import HttpAgentTarget  # noqa: F401
        status["redteam_pkg"] = True
    except Exception as exc:
        status["errors"].append(f"kya_redteam: {exc}")
        logger.warning("[REDTEAM-SIDECAR] warm import redteam_pkg: %s", exc)

    # ── Attacker-LLM reachability probe (M1) ──
    # Check at startup so the operator sees `attacker_llm_standard_reachable:
    # false` in /healthz + container logs rather than discovering it when
    # the first multi-turn campaign fails 30 minutes later.
    if status["redteam_pkg"]:
        try:
            from kya_redteam import describe_configuration
            cfg = describe_configuration()
            std_ok = cfg.get("standard_reachable", False)
            prem_ok = cfg.get("premium_reachable", False)
            status["attacker_llm_standard_reachable"] = std_ok
            status["attacker_llm_premium_reachable"] = prem_ok
            if not std_ok and not prem_ok:
                msg = ("no attacker LLM reachable — multi-turn campaigns "
                       "will fail. Set one of OPENAI_API_KEY, GROQ_API_KEY, "
                       "ANTHROPIC_API_KEY, or OPENROUTER_API_KEY.")
                status["warnings"].append(msg)
                logger.warning("[REDTEAM-SIDECAR] %s", msg)
            elif not std_ok:
                msg = ("standard-tier attacker LLM not reachable — Standard "
                       "tier multi-turn campaigns will fail")
                status["warnings"].append(msg)
                logger.warning("[REDTEAM-SIDECAR] %s", msg)
            elif not prem_ok:
                msg = ("premium-tier attacker LLM not reachable — Premium "
                       "tier campaigns will fall back to fallback chain")
                status["warnings"].append(msg)
                logger.info("[REDTEAM-SIDECAR] %s", msg)
        except Exception as exc:
            logger.warning("[REDTEAM-SIDECAR] LLM probe failed: %s", exc)

        # ── Target-vault key probe ──
        try:
            from kya_redteam import is_encryption_configured
            vault_ok = is_encryption_configured()
            status["target_vault_key_configured"] = vault_ok
            if not vault_ok:
                msg = ("KYA_REDTEAM_SECRET_KEY not set — persistent target "
                       "creation will fail (only ad-hoc target_endpoint+token "
                       "campaigns will work).")
                status["warnings"].append(msg)
                logger.warning("[REDTEAM-SIDECAR] %s", msg)
        except Exception as exc:
            logger.warning("[REDTEAM-SIDECAR] vault probe failed: %s", exc)

    return status


def create_app() -> FastAPI:
    """Factory — pre-warms heavy imports + registers the sidecar
    auth dependency at app level so every NEW route under /v1/* is
    authenticated by default (no per-endpoint forgetting)."""
    warm_status = _warm_imports()
    if warm_status["errors"]:
        logger.warning(
            "[REDTEAM-SIDECAR] starting with degraded imports: %s",
            warm_status["errors"],
        )

    app = FastAPI(
        title="KYA Red-Team Sidecar",
        version="1.0.0",
        description=(
            "Out-of-process runner for KYA red-team campaigns. "
            "Internal-only — auth via KYA_REDTEAM_SIDECAR_SECRET."
        ),
    )

    # Sub-router that ALL protected endpoints register on. The
    # `dependencies=[Depends(require_sidecar_auth)]` is the app-level
    # auth gate — new endpoints added to this router inherit auth.
    from fastapi import APIRouter
    auth_router = APIRouter(
        prefix="/v1",
        dependencies=[Depends(require_sidecar_auth)],
    )

    @app.get("/healthz")
    def healthz():
        """Cheap liveness probe — no DB / Valkey reachability checks here
        (those are exercised by /v1/config). k8s/docker uses this for
        the basic 'is the process up?' question. Public — no auth."""
        return {"ok": True, "service": "vd-kya-redteam",
                "warm_imports": warm_status}

    @auth_router.get("/config")
    def get_config():
        """Operator visibility: which LLMs are reachable, whether the
        target-secret key is configured, PyRIT status, thread-pool
        size, warm-import status."""
        from kya_redteam import (
            describe_configuration,
            is_encryption_configured,
            pyrit_status,
        )
        return {
            "service": "vd-kya-redteam",
            "attacker_llm": describe_configuration(),
            "target_encryption_configured": is_encryption_configured(),
            "pyrit": pyrit_status().to_dict(),
            "max_concurrent_runs": int(
                os.environ.get("KYA_REDTEAM_MAX_CONCURRENT_RUNS", "3"),
            ),
            "warm_imports": warm_status,
        }

    @auth_router.post("/runs", status_code=202)
    def submit_run(body: RunRequest):
        """Submit a campaign run. Returns run_id immediately; the
        caller polls vd-app's /redteam/runs/{run_id} (which reads from
        the shared DB) for status."""
        from db.database import SessionLocal  # type: ignore

        from kya_redteam import (
            materialize_target,
            run_campaign_async,
        )
        from kya_redteam.pyrit_target import HttpAgentTarget

        # Resolve target — same logic as vd-app's _resolve_run_target
        if body.target_id is not None and body.target_endpoint:
            raise HTTPException(
                400,
                "supply either target_id or target_endpoint, not both",
            )
        if body.target_id is not None:
            with SessionLocal() as db:
                try:
                    target = materialize_target(db, body.tenant_id, body.target_id)
                except Exception as exc:
                    raise HTTPException(404, f"target {body.target_id}: {exc}")
        elif body.target_endpoint:
            target = HttpAgentTarget(
                endpoint_url=body.target_endpoint,
                token=body.target_token or "",
                agent_key=body.campaign["agent_key"],
                timeout_s=body.target_timeout_s,
                body_template=body.target_body_template,
                rate_limit_rps=body.target_rate_limit_rps,
                rate_limit_key=(
                    f"{body.tenant_id}:adhoc:sidecar"
                ),
            )
        else:
            raise HTTPException(
                400,
                "either target_id OR target_endpoint required",
            )

        try:
            run_id = run_campaign_async(
                body.campaign,
                target=target,
                target_id=body.target_id,
                initiated_by=body.initiated_by,
                dataset_override=body.dataset_override,
            )
        except Exception as exc:
            logger.exception("[REDTEAM-SIDECAR] submit failed: %s", exc)
            raise HTTPException(500, f"submit failed: {exc}")
        return {
            "run_id": run_id,
            "status": "queued",
            "campaign_id": int(body.campaign["id"]),
            "agent_key": body.campaign["agent_key"],
            "tenant_id": body.tenant_id,
        }

    @auth_router.post("/runs/{run_id}/cancel")
    def cancel_run(run_id: str):
        """Idempotent cancel proxy. The cancel flag goes to Valkey + DB
        immediately; whichever sidecar replica is actually running the
        thread observes it on its next loop iteration.

        Why expose cancel here ALSO (vd-app's /cancel does the same):
        when vd-app is down but the sidecar is up, an operator can hit
        the sidecar directly to stop a runaway run.
        """
        from db.database import SessionLocal  # type: ignore
        from sqlalchemy import text as _sa_text

        from kya._portable import qual_for_raw_sql
        from kya_redteam import request_cancel
        with SessionLocal() as db:
            qual = qual_for_raw_sql(db)
            existing = db.execute(
                _sa_text(
                    f"SELECT tenant_id FROM {qual}kya_redteam_runs "
                    "WHERE run_id = (:rid)::uuid"
                ),
                {"rid": run_id},
            ).fetchone()
            if not existing:
                raise HTTPException(404, f"run {run_id} not found")
            tenant_id = str(existing[0])
            request_cancel(db, run_id, by_user_id=None)
            return {"cancel_requested": True, "run_id": run_id,
                    "tenant_id": tenant_id}

    @auth_router.get("/runs/{run_id}")
    def get_run_status(run_id: str):
        """Sidecar-side run status. vd-app's /redteam/runs/{run_id} is
        the canonical UI surface; this endpoint exists for operators
        who want to talk to the sidecar directly during incident
        response."""
        from db.database import SessionLocal  # type: ignore
        from sqlalchemy import text as _sa_text

        from kya._portable import qual_for_raw_sql
        with SessionLocal() as db:
            qual = qual_for_raw_sql(db)
            row = db.execute(
                _sa_text(
                    f"SELECT tenant_id FROM {qual}kya_redteam_runs "
                    "WHERE run_id = (:rid)::uuid"
                ),
                {"rid": run_id},
            ).fetchone()
            if not row:
                raise HTTPException(404, f"run {run_id} not found")
            from kya_redteam import get_run
            return get_run(db, str(row[0]), run_id)

    # ── Graceful shutdown — drain the thread pool on SIGTERM ────────
    @app.on_event("shutdown")
    def _drain_thread_pool():
        """When the sidecar gets SIGTERM, refuse new submissions and
        wait up to KYA_REDTEAM_SHUTDOWN_DRAIN_S seconds for in-flight
        runs to finish.

        Runs still in flight when the timeout expires get caught by the
        heartbeat-timeout sweep (5 min) so eventual consistency is
        preserved — but draining cleanly avoids that 5-min ghost window.
        """
        try:
            from kya_redteam.runs import _POOL
            if _POOL is None:
                return
            drain_s = float(os.environ.get("KYA_REDTEAM_SHUTDOWN_DRAIN_S", "60"))
            logger.info(
                "[REDTEAM-SIDECAR] SIGTERM received — draining thread pool "
                "(timeout=%.0fs)", drain_s,
            )
            # shutdown(wait=True) blocks until tasks finish OR cancels
            # them via cancel_futures (Py 3.9+). We use wait+cancel so
            # already-running tasks complete but queued ones drop.
            try:
                _POOL.shutdown(wait=True, cancel_futures=True)
            except TypeError:
                # Py <3.9: no cancel_futures kwarg
                _POOL.shutdown(wait=True)
            logger.info("[REDTEAM-SIDECAR] thread pool drained")
        except Exception as exc:
            logger.warning("[REDTEAM-SIDECAR] shutdown drain error: %s", exc)

    app.include_router(auth_router)
    return app


# ── Entrypoint ──────────────────────────────────────────────────────

# Module-level `app` so `uvicorn kya_redteam.server:app` works.
app = create_app()


def main():
    """`python -m kya_redteam.server` — runs uvicorn on the
    configured port. Production deployments should run uvicorn directly
    with `--workers N` to scale across CPUs."""
    import uvicorn
    port = int(os.environ.get("KYA_REDTEAM_SIDECAR_PORT", "8500"))
    workers = int(os.environ.get("KYA_REDTEAM_SIDECAR_WORKERS", "1"))
    logger.info(
        "[REDTEAM-SIDECAR] starting on :%d workers=%d", port, workers,
    )
    uvicorn.run(
        "kya_redteam.server:app",
        host="0.0.0.0",
        port=port,
        workers=workers,
        log_level=os.environ.get("KYA_REDTEAM_LOG_LEVEL", "info").lower(),
    )


if __name__ == "__main__":
    main()
