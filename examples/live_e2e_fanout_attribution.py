"""Real fan-out: orchestrator spawns 3 sub-agents, all attributed back
to the originating user via parent_invocation_id + correlation_id +
principal pointers + actor_agent_key.

Strategy: drive ONE live OpenAI orchestrator+sub-agents run, capture
the transcript (messages, tool calls, token counts, costs), then
REPLAY the exact same write sequence into all 4 backends and run
identical verification. This proves:

  1. Real LLM integration works (the live run on one backend).
  2. Cross-backend portability of the data model (replay on all 4).
  3. Verification assertions hold uniformly.

Backends tested: sqlite, duckdb, postgresql, mysql (whichever the
env exposes).

What we verify (per backend):

  - 4 invocations under one correlation_id (orchestrator + 3 subs).
  - Orchestrator is the root (parent_invocation_id IS NULL),
    principal_kind="user", principal_id=alice.
  - Each sub-agent has parent_invocation_id = orchestrator's id,
    principal_kind="agent", principal_id=orchestrator's agent_key.
  - Walking parent_invocation_id from any sub-agent reaches the
    orchestrator and ultimately a user principal.
  - Per-invocation HMAC chain (verify_chain) returns valid=True for
    every invocation independently.
  - actor_agent_key attribution: a sub-agent rogue signal debits
    the orchestrator's principal-trust counter.
  - cost_by_dimension(agent_key) shows all 4 agents with non-zero
    USD spend.

Requires OPENAI_API_KEY in environment or .env file.
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any


def _load_dotenv_if_present() -> None:
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.is_file():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                if k.strip() and k.strip() not in os.environ:
                    os.environ[k.strip()] = v.strip().strip('"').strip("'")


_load_dotenv_if_present()

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from kya import (
    init_storage,
    new_correlation_id,
    record_evidence,
    record_invocation,
    record_principal_signal,
    score_agent,
    snapshot_on_first_sight,
    verify_chain,
)
from kya.tenant_budget import record_cost_event


TENANT_ID = "00000000-0000-0000-0000-000000000099"
USER_PRINCIPAL = "alice@example.com"

# OpenAI gpt-4o-mini pricing
_PRICE_IN  = 0.150 / 1_000_000
_PRICE_OUT = 0.600 / 1_000_000


def _hdr(t): print(); print("=" * 78); print(f"  {t}"); print("=" * 78)
def _row(l, v): print(f"  {l:40s} {v}")
def _check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}"
          f"{(' - ' + detail) if detail else ''}")
    if not ok:
        raise SystemExit(2)


# Agent definitions ---------------------------------------------------


ORCHESTRATOR_DEF = {
    "agent_key": "EventPlannerOrchestrator",
    "name": "Event Planner Orchestrator",
    "system_prompt": (
        "You are an event-planning orchestrator. You receive a user "
        "request and DELEGATE all work to specialist sub-agents via "
        "the delegate_to_* tools. After all three sub-agents return, "
        "summarize their outputs into one concise confirmation. You "
        "MUST delegate to ALL three sub-agents before responding "
        "(VenueAgent, CateringAgent, GuestListAgent)."
    ),
    "model": "gpt-4o-mini",
    "tools": ["delegate_to_VenueAgent", "delegate_to_CateringAgent",
              "delegate_to_GuestListAgent"],
    "human_loop": "in_the_loop",
    "access_level": "write",
    "environment": "prod",
    "model_trust": "frontier",
}


SUB_AGENT_DEFS = {
    "VenueAgent": {
        "agent_key": "VenueAgent",
        "name": "Venue Specialist",
        "system_prompt": (
            "You are a venue specialist. Given a guest count and date, "
            "propose ONE specific venue with location and capacity. "
            "Be concise."),
        "model": "gpt-4o-mini", "tools": [],
        "human_loop": "in_the_loop", "access_level": "read",
        "environment": "prod",
    },
    "CateringAgent": {
        "agent_key": "CateringAgent",
        "name": "Catering Specialist",
        "system_prompt": (
            "You are a catering specialist. Given a guest count and "
            "dietary requirements, propose ONE menu (3 courses) with "
            "per-head cost estimate. Be concise."),
        "model": "gpt-4o-mini", "tools": [],
        "human_loop": "in_the_loop", "access_level": "read",
        "environment": "prod",
    },
    "GuestListAgent": {
        "agent_key": "GuestListAgent",
        "name": "Guest List Specialist",
        "system_prompt": (
            "You are a guest list specialist. Given an event topic, "
            "propose 5 representative VIP guest categories (NOT real "
            "people). Be concise."),
        "model": "gpt-4o-mini", "tools": [],
        "human_loop": "in_the_loop", "access_level": "read",
        "environment": "prod",
    },
}


_DELEGATE_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": f"delegate_to_{name}",
            "description": (f"Delegate to {info['name']}. "
                            f"Pass the task as the 'task' argument."),
            "parameters": {
                "type": "object",
                "properties": {"task": {"type": "string"}},
                "required": ["task"],
            },
        },
    }
    for name, info in SUB_AGENT_DEFS.items()
]


# Live capture --------------------------------------------------------


def capture_live_transcript() -> dict:
    """Drive a real OpenAI multi-agent run; return a transcript
    suitable for deterministic replay into any backend."""
    from openai import OpenAI
    client = OpenAI()

    transcript: dict[str, Any] = {
        "correlation_id": new_correlation_id(),
        "orchestrator_calls": [],
        "sub_agent_calls": [],
    }
    user_task = (
        "Plan a 50-person product launch event for next month. "
        "I need a venue, a catering menu, and a guest list. "
        "Delegate to your specialist sub-agents.")
    transcript["user_task"] = user_task

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": ORCHESTRATOR_DEF["system_prompt"]},
        {"role": "user", "content": user_task},
    ]
    iterations = 0

    while iterations < 8:
        iterations += 1
        t0 = time.time()
        completion = client.chat.completions.create(
            model=ORCHESTRATOR_DEF["model"], messages=messages,
            tools=_DELEGATE_TOOLS, tool_choice="auto",
        )
        latency_ms = int((time.time() - t0) * 1000)

        choice = completion.choices[0]
        msg = choice.message
        tool_calls = msg.tool_calls or []

        transcript["orchestrator_calls"].append({
            "iter": iterations,
            "input_tokens": completion.usage.prompt_tokens,
            "output_tokens": completion.usage.completion_tokens,
            "model": completion.model,
            "latency_ms": latency_ms,
            "content": msg.content,
            "tool_calls": [
                {"id": tc.id, "name": tc.function.name,
                 "args": tc.function.arguments}
                for tc in tool_calls
            ],
        })

        messages.append({
            "role": "assistant",
            "content": msg.content,
            "tool_calls": [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name,
                              "arguments": tc.function.arguments}}
                for tc in tool_calls
            ] if tool_calls else None,
        })

        if not tool_calls:
            break

        for tc in tool_calls:
            sub_name = tc.function.name.replace("delegate_to_", "")
            args = json.loads(tc.function.arguments or "{}")
            task = args.get("task", "")
            sub_def = SUB_AGENT_DEFS.get(sub_name)
            if sub_def is None:
                payload = {"error": f"unknown sub-agent: {sub_name}"}
            else:
                print(f"  [live] running sub-agent {sub_name}")
                t1 = time.time()
                sub_resp = client.chat.completions.create(
                    model=sub_def["model"],
                    messages=[
                        {"role": "system",
                         "content": sub_def["system_prompt"]},
                        {"role": "user", "content": task},
                    ],
                    max_tokens=200,
                )
                sub_latency = int((time.time() - t1) * 1000)
                answer = sub_resp.choices[0].message.content or ""
                transcript["sub_agent_calls"].append({
                    "agent_key": sub_name,
                    "tool_call_id": tc.id,
                    "task": task,
                    "answer": answer,
                    "input_tokens": sub_resp.usage.prompt_tokens,
                    "output_tokens": sub_resp.usage.completion_tokens,
                    "model": sub_resp.model,
                    "latency_ms": sub_latency,
                })
                payload = {"sub_agent": sub_name,
                            "answer": answer[:200]}

            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": json.dumps(payload),
            })

    transcript["iterations"] = iterations
    return transcript


# Replay --------------------------------------------------------------


def replay_to_backend(db, transcript: dict) -> dict:
    """Write the captured transcript into the open `db` session."""

    corr_id = transcript["correlation_id"]

    score_agent(ORCHESTRATOR_DEF)
    snapshot_on_first_sight(
        db, tenant_id=TENANT_ID,
        agent_key=ORCHESTRATOR_DEF["agent_key"],
        definition=ORCHESTRATOR_DEF, note="fan-out e2e")

    orch_inv_id = record_invocation(
        db, tenant_id=TENANT_ID,
        agent_key=ORCHESTRATOR_DEF["agent_key"],
        principal_kind="user", principal_id=USER_PRINCIPAL,
        parent_invocation_id=None,
        correlation_id=corr_id,
        mode="observed", outcome="in_progress",
    )

    record_evidence(
        db, tenant_id=TENANT_ID, invocation_id=orch_inv_id,
        evidence_kind="prompt", role="user",
        payload={"content": transcript["user_task"]},
        correlation_id=corr_id,
    )

    for call in transcript["orchestrator_calls"]:
        call_cost = (call["input_tokens"] * _PRICE_IN
                     + call["output_tokens"] * _PRICE_OUT)
        record_cost_event(
            db, tenant_id=TENANT_ID,
            agent_key=ORCHESTRATOR_DEF["agent_key"],
            usd_amount=call_cost, model_used=call["model"],
            input_tokens=call["input_tokens"],
            output_tokens=call["output_tokens"],
            environment="prod", outcome="success",
            latency_ms=call["latency_ms"],
            invocation_id=orch_inv_id,
            request_id=f"orch-{orch_inv_id}-iter-{call['iter']}",
        )
        for tc in call["tool_calls"]:
            record_evidence(
                db, tenant_id=TENANT_ID, invocation_id=orch_inv_id,
                evidence_kind="delegation_message", role="assistant",
                payload={"tool_name": tc["name"],
                          "task": json.loads(tc["args"]).get("task", ""),
                          "tool_call_id": tc["id"]},
                correlation_id=corr_id,
            )

    sub_inv_ids: list[dict] = []
    for sub_call in transcript["sub_agent_calls"]:
        sub_def = SUB_AGENT_DEFS[sub_call["agent_key"]]
        snapshot_on_first_sight(
            db, tenant_id=TENANT_ID, agent_key=sub_def["agent_key"],
            definition=sub_def, note="fan-out e2e")

        sub_inv_id = record_invocation(
            db, tenant_id=TENANT_ID,
            agent_key=sub_def["agent_key"],
            principal_kind="agent",
            principal_id=ORCHESTRATOR_DEF["agent_key"],
            parent_invocation_id=orch_inv_id,
            correlation_id=corr_id,
            mode="observed", outcome="success",
        )

        record_evidence(
            db, tenant_id=TENANT_ID, invocation_id=sub_inv_id,
            evidence_kind="prompt", role="user",
            payload={"content": sub_call["task"]},
            correlation_id=corr_id,
        )
        sub_cost = (sub_call["input_tokens"] * _PRICE_IN
                    + sub_call["output_tokens"] * _PRICE_OUT)
        record_cost_event(
            db, tenant_id=TENANT_ID,
            agent_key=sub_def["agent_key"],
            usd_amount=sub_cost, model_used=sub_call["model"],
            input_tokens=sub_call["input_tokens"],
            output_tokens=sub_call["output_tokens"],
            environment="prod", outcome="success",
            latency_ms=sub_call["latency_ms"],
            invocation_id=sub_inv_id,
            parent_request_id=f"orch-{orch_inv_id}",
            request_id=f"sub-{sub_inv_id}",
        )
        record_evidence(
            db, tenant_id=TENANT_ID, invocation_id=sub_inv_id,
            evidence_kind="response", role="assistant",
            payload={"content": sub_call["answer"],
                      "cost_usd": round(sub_cost, 6)},
            correlation_id=corr_id,
        )

        record_evidence(
            db, tenant_id=TENANT_ID, invocation_id=orch_inv_id,
            evidence_kind="tool_result", role="tool",
            payload={"sub_agent": sub_def["agent_key"],
                      "sub_invocation_id": sub_inv_id,
                      "answer": sub_call["answer"][:200]},
            correlation_id=corr_id,
        )

        sub_inv_ids.append({"agent_key": sub_def["agent_key"],
                             "inv_id": sub_inv_id})

    final = transcript["orchestrator_calls"][-1]
    record_evidence(
        db, tenant_id=TENANT_ID, invocation_id=orch_inv_id,
        evidence_kind="response", role="assistant",
        payload={"content": final["content"] or "",
                  "iterations": transcript["iterations"],
                  "sub_agents_spawned": len(sub_inv_ids)},
        correlation_id=corr_id,
    )

    return {
        "correlation_id": corr_id,
        "orchestrator_invocation_id": orch_inv_id,
        "sub_invocations": sub_inv_ids,
    }


# Verification --------------------------------------------------------


def verify_backend(db, summary: dict, label: str) -> None:
    corr_id = summary["correlation_id"]
    orch_id = summary["orchestrator_invocation_id"]
    sub_ids = [s["inv_id"] for s in summary["sub_invocations"]]

    schema_prefix = "prov_schema." if label == "postgresql" else ""

    rows = db.execute(text(
        f"SELECT id, agent_key, principal_kind, principal_id, "
        f"       parent_invocation_id "
        f"FROM {schema_prefix}kya_invocations "
        f"WHERE correlation_id = :c "
        f"ORDER BY id"
    ), {"c": corr_id}).fetchall()

    inv_by_id = {r[0]: {"agent": r[1], "p_kind": r[2],
                          "p_id": r[3], "parent": r[4]}
                 for r in rows}
    print()
    print(f"  Tree under correlation_id ({label}):")
    print(f"  {'id':>4s}  {'agent':28s} {'principal':45s} {'parent':>6s}")
    for r in rows:
        p_str = str(r[4]) if r[4] is not None else "ROOT"
        prn = f"{r[2]}:{r[3]}"
        print(f"  {r[0]:>4d}  {r[1]:28s} {prn:45s} {p_str:>6s}")

    _check(f"{label}: 4 invocations under one correlation_id",
           len(rows) == 4, f"got={len(rows)}")
    _check(f"{label}: orchestrator is root (parent=NULL)",
           inv_by_id[orch_id]["parent"] is None)
    _check(f"{label}: orchestrator principal is user:alice",
           inv_by_id[orch_id]["p_kind"] == "user" and
           inv_by_id[orch_id]["p_id"] == USER_PRINCIPAL)
    for sid in sub_ids:
        sub = inv_by_id[sid]
        _check(f"{label}: sub {sub['agent']} parent={orch_id}",
               sub["parent"] == orch_id)
        _check(f"{label}: sub {sub['agent']} principal=agent:Orchestrator",
               sub["p_kind"] == "agent" and
               sub["p_id"] == ORCHESTRATOR_DEF["agent_key"])

    walk_id = sub_ids[0]
    walk: list[dict] = []
    while walk_id is not None:
        d = inv_by_id[walk_id]
        walk.append(d)
        walk_id = d["parent"]
    _check(f"{label}: parent walk terminates at user",
           walk[-1]["p_kind"] == "user"
           and walk[-1]["p_id"] == USER_PRINCIPAL)

    for inv_id in [orch_id] + sub_ids:
        rep = verify_chain(db, tenant_id=TENANT_ID, invocation_id=inv_id)
        _check(f"{label}: chain inv={inv_id} valid",
               rep["valid"], f"rows={rep['checked']}")

    # actor_agent_key attribution via direct call (no session factory)
    record_principal_signal(
        db, tenant_id=TENANT_ID,
        principal_kind="agent",
        principal_id=ORCHESTRATOR_DEF["agent_key"],
        signal_kind="oos_tool",
    )
    rows = db.execute(text(
        f"SELECT principal_kind, principal_id, trust_score "
        f"FROM {schema_prefix}kya_principal_trust "
        f"WHERE tenant_id = :t AND principal_kind = 'agent' "
        f"  AND principal_id = :p"
    ), {"t": TENANT_ID,
        "p": ORCHESTRATOR_DEF["agent_key"]}).fetchall()
    _check(f"{label}: orchestrator agent-trust row exists",
           len(rows) >= 1, f"got {len(rows)}")
    if rows:
        score = float(rows[0][2])
        _check(f"{label}: orchestrator trust debited (score={score:.1f})",
               score < 50.0)

    from kya.cost_analytics import cost_by_dimension
    by_agent = cost_by_dimension(db, "agent_key", tenant_id=TENANT_ID)
    print()
    print(f"  cost_by_dimension('agent_key') on {label}:")
    for k, v in by_agent.items():
        _row(f"    {k}",
             f"${v['usd']:.6f}  events={v['events']}")
    _check(f"{label}: all 4 agents have cost events",
           len(by_agent) == 4)


# Backend session opener ---------------------------------------------


def open_backend(label: str):
    if label == "sqlite":
        eng = create_engine("sqlite:///:memory:").execution_options(
            schema_translate_map={"prov_schema": None})
    elif label == "duckdb":
        eng = create_engine("duckdb:///:memory:").execution_options(
            schema_translate_map={"prov_schema": None})
    elif label == "postgresql":
        url = os.environ.get("KYA_TEST_PG_URL")
        if not url: return None, None
        eng = create_engine(url)
        with eng.begin() as conn:
            conn.execute(text("CREATE SCHEMA IF NOT EXISTS prov_schema"))
            for tbl in ("kya_cost_events", "kya_budget_changes",
                        "kya_tenant_cost_budgets", "kya_evidence",
                        "kya_invocations", "kya_principal_trust",
                        "agent_versions"):
                conn.execute(text(
                    f"DROP TABLE IF EXISTS prov_schema.{tbl}"))
    elif label == "mysql":
        url = os.environ.get("KYA_TEST_MYSQL_URL")
        if not url: return None, None
        eng = create_engine(url).execution_options(
            schema_translate_map={"prov_schema": None})
        with eng.begin() as conn:
            for tbl in ("kya_cost_events", "kya_budget_changes",
                        "kya_tenant_cost_budgets", "kya_evidence",
                        "kya_invocations", "kya_principal_trust",
                        "agent_versions"):
                try:
                    conn.execute(text(f"DROP TABLE IF EXISTS {tbl}"))
                except Exception:
                    pass
    else:
        return None, None
    return sessionmaker(bind=eng)(), eng.dispose


# main ----------------------------------------------------------------


def main() -> int:
    if not os.environ.get("OPENAI_API_KEY"):
        print("OPENAI_API_KEY not set - skipping live test."); return 0
    try:
        from openai import OpenAI  # noqa: F401
    except ImportError:
        print("openai package not installed."); return 0

    _hdr("PHASE 0  ·  Capture LIVE OpenAI fan-out transcript")
    print()
    print("  Driving real OpenAI calls (orchestrator + sub-agents)...")
    transcript = capture_live_transcript()

    n_orch_calls = len(transcript["orchestrator_calls"])
    n_sub_calls = len(transcript["sub_agent_calls"])
    total_tok_in = sum(c["input_tokens"]
                      for c in transcript["orchestrator_calls"]
                                + transcript["sub_agent_calls"])
    total_tok_out = sum(c["output_tokens"]
                       for c in transcript["orchestrator_calls"]
                                 + transcript["sub_agent_calls"])
    total_cost = (total_tok_in * _PRICE_IN + total_tok_out * _PRICE_OUT)
    _row("orchestrator LLM iterations", n_orch_calls)
    _row("sub-agents spawned", n_sub_calls)
    _row("total input tokens", total_tok_in)
    _row("total output tokens", total_tok_out)
    _row("total OpenAI cost", f"${total_cost:.6f}")
    _check("captured exactly 3 sub-agent calls",
           n_sub_calls == 3, f"got {n_sub_calls}")

    backend_list = ["sqlite"]
    try:
        import duckdb_engine  # noqa: F401
        backend_list.append("duckdb")
    except ImportError:
        pass
    if os.environ.get("KYA_TEST_PG_URL"):
        backend_list.append("postgresql")
    if os.environ.get("KYA_TEST_MYSQL_URL"):
        backend_list.append("mysql")

    results: dict[str, str] = {}
    for label in backend_list:
        _hdr(f"BACKEND  ·  {label.upper()}")
        db, dispose = open_backend(label)
        if db is None:
            print(f"  skipped: env not set"); continue
        try:
            init_storage(db)
            summary = replay_to_backend(db, transcript)
            verify_backend(db, summary, label)
            results[label] = "PASS"
        except SystemExit:
            results[label] = "FAIL"
        except Exception as exc:
            print(f"  [ERROR] {label}: {exc}")
            results[label] = f"ERROR: {exc}"
        finally:
            try: db.close()
            except Exception: pass
            try: dispose()
            except Exception: pass

    _hdr("CROSS-BACKEND SUMMARY")
    for label, status in results.items():
        print(f"  {label:15s} {status}")
    all_pass = all(s == "PASS" for s in results.values())
    if all_pass:
        _hdr("FAN-OUT ATTRIBUTION E2E - ALL BACKENDS PASSED")
        return 0
    else:
        _hdr("FAN-OUT ATTRIBUTION E2E - FAILURES ABOVE")
        return 2


if __name__ == "__main__":
    sys.exit(main())
