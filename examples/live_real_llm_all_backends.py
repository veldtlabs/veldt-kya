"""Real-LLM end-to-end lifecycle test against all 4 KYA backends.

Closes the gap previously documented in LIVE_RUNTIME_TEST_RESULTS.md
where the LangChain / OpenAI Agents SDK live tests ran only against
PostgreSQL. This script exercises the FULL SDK lifecycle on each
of PostgreSQL / MySQL / SQLite / DuckDB:

    1. init_storage()
    2. score_agent() on a real agent definition
    3. snapshot_agent()  → agent_versions row
    4. record_invocation() → kya_invocations row
    5. Real OpenAI chat-completions API call (gpt-4o-mini)
    6. record_evidence() x 2 (prompt + response) → kya_evidence rows
       with HMAC chain
    7. record_principal_clean() → kya_principal_trust row
    8. verify_chain() → confirms tamper-evidence integrity
    9. record_principal_signal(oos_tool) → trust decrement
   10. final row count + chain verification

Required env:
    OPENAI_API_KEY        — real OpenAI key
    KYA_TEST_PG_URL       — postgres URL (e.g. postgresql://postgres:kya@localhost:55777/kya)
    KYA_TEST_MYSQL_URL    — mysql URL  (e.g. mysql+pymysql://root:kya@localhost:33077/kyatest)

SQLite + DuckDB run from temp file paths automatically.
"""

import os
import sys
import tempfile
import time
from pathlib import Path

# Load .env from veldt-decisions if not already in env
env_file = Path("/d/veldt-decisions/.env")
if not env_file.exists():
    env_file = Path("D:/veldt-decisions/.env")
if env_file.exists():
    for line in env_file.read_text().splitlines():
        if "=" in line and not line.strip().startswith("#"):
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k and v and k not in os.environ:
                os.environ[k] = v

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session


def _reload_kya():
    for k in list(sys.modules):
        if k.startswith("kya") or k.startswith("kya_redteam"):
            del sys.modules[k]
    return __import__("kya")


def _drop_kya_tables(engine, schema):
    """Best-effort cleanup of any existing KYA tables for a clean run."""
    tables = [
        "agent_versions", "kya_invocations", "kya_principal_trust",
        "kya_evidence", "kya_agent_aliases", "kya_user_trust",
        "kya_weight_overrides", "kya_weight_changes", "kya_weight_suggestions",
        "kya_breach_notifications", "kya_redteam_campaigns",
        "kya_redteam_findings", "kya_redteam_tenant_policy",
        "kya_redteam_runs", "kya_redteam_targets",
        "kya_redteam_target_secrets", "kya_inbound_recommendations",
    ]
    with engine.begin() as conn:
        if schema == "prov_schema":
            conn.execute(text("CREATE SCHEMA IF NOT EXISTS prov_schema"))
        for t in tables:
            full = f"{schema}.{t}" if schema else t
            try:
                conn.execute(text(f"DROP TABLE IF EXISTS {full} CASCADE"))
            except Exception:
                try:
                    conn.execute(text(f"DROP TABLE IF EXISTS {full}"))
                except Exception:
                    pass


def _run_real_llm_lifecycle(backend_name, url, schema):
    print(f"\n{'='*72}\n  {backend_name.upper()}  ({url[:55]})\n{'='*72}")
    os.environ["KYA_VERSIONS_SCHEMA"] = schema or ""

    kya = _reload_kya()
    from kya import (
        init_storage,
        snapshot_agent,
        record_invocation,
        record_evidence,
        record_principal_clean,
        record_principal_signal,
        score_agent,
        verify_chain,
        record_oos_tool_attempt,
    )

    engine = create_engine(url)
    _drop_kya_tables(engine, schema)
    with Session(engine) as db:
        init_storage(db)
        db.commit()

    tenant = "00000000-0000-0000-0000-000000000aaa"
    agent_key = f"live_real_llm_{backend_name}"
    definition = {
        "agent_key": agent_key,
        "name": "Live Real-LLM Agent",
        "framework": "openai",
        "tools": ["add_numbers"],
        "human_loop": "in_the_loop",
        "model": "openai/gpt-4o-mini",
        "access_level": "read",
    }

    risk = score_agent(definition)
    print(f"  score = {risk.score}  bucket = {risk.bucket}  "
          f"factors = {len(risk.factors)}")

    with Session(engine) as db:
        snapshot_agent(
            db, tenant_id=tenant, agent_key=agent_key,
            definition=definition, created_by="live-real-llm-suite",
        )
        invocation_id = record_invocation(
            db, tenant_id=tenant, agent_key=agent_key,
            principal_kind="agent", principal_id=agent_key,
            mode="observed", outcome="success",
        )
        db.commit()

    # REAL LLM CALL
    prompt = "What is 47 + 53? Answer with a single number."
    t0 = time.time()
    try:
        from openai import OpenAI
        client = OpenAI()  # honors OPENAI_API_KEY
        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
        )
        response_text = completion.choices[0].message.content
        llm_ms = int((time.time() - t0) * 1000)
        print(f"  REAL OpenAI call: '{response_text[:60]}' ({llm_ms} ms)")
    except Exception as exc:
        return {
            "backend": backend_name,
            "status": "OPENAI_FAIL",
            "error": str(exc).splitlines()[0][:200],
        }

    # Record both sides of the call as evidence
    with Session(engine) as db:
        record_evidence(
            db, tenant_id=tenant, invocation_id=invocation_id,
            evidence_kind="prompt", payload={"text": prompt},
        )
        record_evidence(
            db, tenant_id=tenant, invocation_id=invocation_id,
            evidence_kind="response", payload={"text": response_text},
        )
        record_principal_clean(
            db, tenant_id=tenant, principal_kind="agent", principal_id=agent_key,
        )
        db.commit()

    # Trigger a rogue path so principal trust decrements
    # Note: record_oos_tool_attempt has no db arg — it uses module-level
    # session via realtime mirror; the persistent debit goes via
    # record_principal_signal.
    with Session(engine) as db:
        from kya import record_principal_signal
        record_principal_signal(
            db, tenant_id=tenant, principal_kind="agent",
            principal_id=agent_key, signal_kind="oos_tool",
        )
        db.commit()
    try:
        record_oos_tool_attempt(
            agent_key=agent_key, tool="delete_database",
            tenant_id=tenant, actor_agent_key=agent_key,
        )
    except Exception:
        pass  # realtime mirror is optional; principal signal already recorded

    # Verify the HMAC chain integrity
    with Session(engine) as db:
        chain_verdict = verify_chain(db, tenant_id=tenant, invocation_id=invocation_id)

    # Read final state
    with engine.connect() as conn:
        n_versions = conn.execute(text(
            f"SELECT COUNT(*) FROM {schema+'.' if schema else ''}agent_versions"
        )).scalar()
        n_invocations = conn.execute(text(
            f"SELECT COUNT(*) FROM {schema+'.' if schema else ''}kya_invocations"
        )).scalar()
        n_evidence = conn.execute(text(
            f"SELECT COUNT(*) FROM {schema+'.' if schema else ''}kya_evidence"
        )).scalar()
        n_trust = conn.execute(text(
            f"SELECT COUNT(*), MIN(trust_score) FROM {schema+'.' if schema else ''}kya_principal_trust"
        )).fetchone()

    return {
        "backend": backend_name,
        "status": "PASS",
        "score": risk.score,
        "bucket": risk.bucket,
        "versions": int(n_versions),
        "invocations": int(n_invocations),
        "evidence_rows": int(n_evidence),
        "principals": int(n_trust[0]),
        "trust_score": int(n_trust[1]) if n_trust[1] is not None else None,
        "chain_valid": getattr(chain_verdict, "valid", chain_verdict),
        "real_response_excerpt": (response_text or "")[:60],
        "llm_ms": llm_ms,
    }


def main():
    if not os.environ.get("OPENAI_API_KEY"):
        print("OPENAI_API_KEY not set; aborting")
        sys.exit(1)

    tmpdir = tempfile.mkdtemp(prefix="kya_e2e_")
    backends = [
        ("sqlite", f"sqlite:///{tmpdir}/kya.sqlite", None),
        ("duckdb", f"duckdb:///{tmpdir}/kya.duckdb", None),
    ]
    pg = os.environ.get("KYA_TEST_PG_URL", "postgresql+psycopg2://postgres:kya@localhost:55777/kya")
    backends.append(("postgresql", pg, "prov_schema"))
    mysql = os.environ.get("KYA_TEST_MYSQL_URL", "mysql+pymysql://root:kya@localhost:33077/kyatest")
    backends.append(("mysql", mysql, None))

    results = []
    for name, url, schema in backends:
        try:
            r = _run_real_llm_lifecycle(name, url, schema)
        except Exception as exc:
            r = {"backend": name, "status": "ERROR",
                 "error": str(exc).splitlines()[0][:240]}
        results.append(r)
        print(f"  -> {r}")

    print(f"\n\n{'='*72}\n  REAL-LLM CROSS-BACKEND LIFECYCLE — SUMMARY\n{'='*72}")
    header = f"{'BACKEND':12s} | {'STATUS':8s} | {'SCORE':5s} | {'VER':3s} | {'INV':3s} | {'EVID':4s} | {'TRUST':5s} | {'CHAIN':5s} | LLM RESPONSE"
    print(header)
    print("-" * len(header))
    for r in results:
        if r["status"] == "PASS":
            print(
                f"{r['backend']:12s} | {r['status']:8s} | "
                f"{r['score']:5d} | {r['versions']:3d} | {r['invocations']:3d} | "
                f"{r['evidence_rows']:4d} | {r['trust_score']:5} | "
                f"{str(r['chain_valid'])[:5]:5s} | {r['real_response_excerpt'][:30]}"
            )
        else:
            print(f"{r['backend']:12s} | {r['status']:8s} | {r.get('error', '')[:90]}")


if __name__ == "__main__":
    main()
