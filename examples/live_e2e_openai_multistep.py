"""Real multi-step agent loop driving the FULL evidence chain.

This complements ``live_e2e_budget_governance.py`` by exercising what
the synthetic e2e doesn't: a real OpenAI tool-calling loop that drives
an agent through prompt -> tool_call -> tool_result -> tool_call ->
tool_result -> response, capturing every step as evidence rows.

What this proves on a REAL DB (PG / SQLite / DuckDB / MySQL):

  1. SNAPSHOT-ON-FIRST-SIGHT
       New ``kya.snapshot_on_first_sight()`` helper writes v1 the first
       time the agent is seen, returns the existing version_no on
       subsequent identical-definition calls (idempotent).

  2. EVIDENCE CHAIN GROWTH
       For a 3-tool-call task, the chain grows to ~10+ rows per
       invocation (1 prompt + N tool_call/result pairs + 1 response).
       Each row carries a fresh signed_hash chaining back to its
       predecessor — verify_chain() must return valid=True.

  3. PER-STEP COST ATTRIBUTION
       Every LLM round-trip records a real cost event with the actual
       token counts and computed USD amount. The audit chain links
       to those cost events via invocation_id.

  4. RUNTIME BUDGET ENFORCEMENT
       Before EVERY LLM call, should_refuse() is consulted. If the
       configured cap is breached, the loop aborts cleanly.

Requires OPENAI_API_KEY in environment or .env file.
Skips gracefully (with explanation) if the key isn't present.
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any


# ── .env loader (same pattern as other e2e tests) ───────────────────
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
    score_agent,
    snapshot_on_first_sight,
    verify_chain,
)
from kya.tenant_budget import (
    record_cost_event, set_budget, should_refuse,
)

TENANT_ID = "00000000-0000-0000-0000-000000000042"


# ── Pretty printing ─────────────────────────────────────────────────


def _hdr(title: str) -> None:
    print()
    print("=" * 78)
    print(f"  {title}")
    print("=" * 78)


def _row(label: str, value) -> None:
    print(f"  {label:32s} {value}")


def _check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}"
          f"{(' - ' + detail) if detail else ''}")
    if not ok:
        sys.exit(2)


# ── Synthetic but realistic tools (no external network) ─────────────
# Each tool is a regular Python function. The agent invokes them via
# OpenAI function-calling; results feed back into the conversation.


def lookup_contact(email: str) -> dict:
    """Pretend address-book lookup."""
    fake_book = {
        "bob@example.com": {"name": "Bob Lee", "tz": "America/Los_Angeles",
                             "role": "Engineering Manager"},
        "carol@example.com": {"name": "Carol Lin", "tz": "Europe/London",
                               "role": "Product Lead"},
    }
    return fake_book.get(email, {"error": f"unknown contact: {email}"})


def check_calendar(date: str, participant: str) -> dict:
    """Pretend availability lookup."""
    return {
        "date": date,
        "participant": participant,
        "free_blocks": ["13:00-14:30", "15:00-17:00"],
    }


def propose_meeting_time(
    participants: list[str],
    start_time: str,
    duration_min: int,
) -> dict:
    """Pretend meeting proposal — returns a confirmation token."""
    token = f"mtg-{uuid.uuid4().hex[:8]}"
    return {
        "token": token,
        "participants": participants,
        "start_time": start_time,
        "duration_min": duration_min,
    }


def send_meeting_invite(token: str) -> dict:
    """Pretend invite-send."""
    return {"token": token, "sent": True, "channel": "email"}


_TOOLS_PYTHON = {
    "lookup_contact": lookup_contact,
    "check_calendar": check_calendar,
    "propose_meeting_time": propose_meeting_time,
    "send_meeting_invite": send_meeting_invite,
}


# OpenAI function-calling schemas
_OPENAI_TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "lookup_contact",
            "description": "Look up a contact in the address book by email.",
            "parameters": {
                "type": "object",
                "properties": {
                    "email": {"type": "string"},
                },
                "required": ["email"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_calendar",
            "description": "Check free time blocks for a participant on a date.",
            "parameters": {
                "type": "object",
                "properties": {
                    "date": {"type": "string", "description": "YYYY-MM-DD"},
                    "participant": {"type": "string"},
                },
                "required": ["date", "participant"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "propose_meeting_time",
            "description": "Propose a meeting time and return a confirmation token.",
            "parameters": {
                "type": "object",
                "properties": {
                    "participants": {"type": "array",
                                     "items": {"type": "string"}},
                    "start_time": {"type": "string",
                                   "description": "ISO 8601"},
                    "duration_min": {"type": "integer"},
                },
                "required": ["participants", "start_time", "duration_min"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_meeting_invite",
            "description": "Send the meeting invite using a token from propose_meeting_time.",
            "parameters": {
                "type": "object",
                "properties": {
                    "token": {"type": "string"},
                },
                "required": ["token"],
            },
        },
    },
]


# Agent definition — fed into KYA's scorer + snapshot helpers
AGENT_DEF = {
    "agent_key": "MeetingSchedulerAgent",
    "name": "Meeting Scheduler",
    "description": "Schedules meetings via contact lookup + calendar check + invite.",
    "system_prompt": (
        "You are a precise meeting scheduler. Always: "
        "1) look up the contact, 2) check their calendar, "
        "3) propose a time, 4) send the invite. "
        "Stop after sending one invite."
    ),
    "model": "gpt-4o-mini",
    "tools": list(_TOOLS_PYTHON.keys()),
    "human_loop": "in_the_loop",
    "access_level": "write",
    "data_classes": ["pii"],
    "environment": "prod",
    "model_trust": "frontier",
}


# gpt-4o-mini pricing (Apr 2025 published rates)
_PRICE_IN_USD_PER_TOKEN = 0.150 / 1_000_000
_PRICE_OUT_USD_PER_TOKEN = 0.600 / 1_000_000


# ── Open session ────────────────────────────────────────────────────


def _open_session():
    pg = os.environ.get("KYA_TEST_PG_URL")
    if pg:
        eng = create_engine(pg)
        with eng.begin() as conn:
            conn.execute(text("CREATE SCHEMA IF NOT EXISTS prov_schema"))
            for tbl in ("kya_cost_events", "kya_budget_changes",
                        "kya_tenant_cost_budgets", "kya_evidence",
                        "kya_invocations", "kya_principal_trust",
                        "agent_versions"):
                conn.execute(text(f"DROP TABLE IF EXISTS prov_schema.{tbl}"))
        label = "postgresql"
    else:
        eng = create_engine("sqlite:///:memory:").execution_options(
            schema_translate_map={"prov_schema": None})
        label = "sqlite"
    return sessionmaker(bind=eng)(), label, eng.dispose


# ── The actual multi-step loop ──────────────────────────────────────


def run_agent_loop(
    db,
    user_prompt: str,
    max_iters: int = 10,
) -> dict:
    """Drive an OpenAI function-calling loop and write a KYA evidence
    row at every step. Returns the final summary."""
    from openai import OpenAI
    client = OpenAI()

    corr_id = new_correlation_id()

    # Score the agent (pure function, always safe)
    risk = score_agent(AGENT_DEF)
    _row("agent risk score", f"{risk.score} ({risk.bucket})")

    # Snapshot-on-first-sight — should be NEW the first time
    version_no, is_new = snapshot_on_first_sight(
        db, tenant_id=TENANT_ID, agent_key=AGENT_DEF["agent_key"],
        definition=AGENT_DEF, created_by=None,
        note="auto-snapshot from multi-step e2e",
    )
    _row("snapshot version", f"v{version_no}  (new={is_new})")

    # Calling again with same definition must NOT create a new version
    version_no_2, is_new_2 = snapshot_on_first_sight(
        db, tenant_id=TENANT_ID, agent_key=AGENT_DEF["agent_key"],
        definition=AGENT_DEF,
    )
    _check("snapshot_on_first_sight is idempotent",
           (version_no_2 == version_no) and (is_new_2 is False))

    # Open invocation row
    inv_id = record_invocation(
        db, tenant_id=TENANT_ID, agent_key=AGENT_DEF["agent_key"],
        principal_kind="user", principal_id="alice@example.com",
        correlation_id=corr_id,
        mode="observed", outcome="in_progress",
    )
    _row("invocation_id", inv_id)

    # 1. PROMPT — first evidence row
    record_evidence(
        db, tenant_id=TENANT_ID, invocation_id=inv_id,
        evidence_kind="prompt", role="user",
        payload={"content": user_prompt},
        correlation_id=corr_id,
    )

    messages = [
        {"role": "system", "content": AGENT_DEF["system_prompt"]},
        {"role": "user", "content": user_prompt},
    ]
    total_cost_usd = 0.0
    iterations = 0
    tool_calls_executed = 0
    evidence_rows_written = 1  # the prompt

    while iterations < max_iters:
        iterations += 1
        # Runtime budget check BEFORE each LLM call
        budget_decision = should_refuse(
            db, tenant_id=TENANT_ID, scope="agent",
            scope_key=AGENT_DEF["agent_key"],
            intended_cost_usd=0.01, window="1h",
        )
        if budget_decision.verdict == "refuse":
            _row("BUDGET REFUSE", budget_decision.reason)
            record_evidence(
                db, tenant_id=TENANT_ID, invocation_id=inv_id,
                evidence_kind="system_message",
                payload={"event": "budget_refused",
                          "reason": budget_decision.reason},
                correlation_id=corr_id,
            )
            evidence_rows_written += 1
            break

        # LLM call
        t0 = time.time()
        completion = client.chat.completions.create(
            model=AGENT_DEF["model"],
            messages=messages,
            tools=_OPENAI_TOOL_SCHEMAS,
            tool_choice="auto",
        )
        latency_ms = int((time.time() - t0) * 1000)

        usage = completion.usage
        call_cost = (usage.prompt_tokens * _PRICE_IN_USD_PER_TOKEN
                     + usage.completion_tokens * _PRICE_OUT_USD_PER_TOKEN)
        total_cost_usd += call_cost

        # Record cost event linked to the invocation
        record_cost_event(
            db, tenant_id=TENANT_ID, agent_key=AGENT_DEF["agent_key"],
            usd_amount=call_cost, model_used=completion.model,
            input_tokens=usage.prompt_tokens,
            output_tokens=usage.completion_tokens,
            cost_center="ops", environment="prod",
            outcome="success", latency_ms=latency_ms,
            invocation_id=inv_id,
            request_id=f"loop-{inv_id}-iter-{iterations}",
        )

        choice = completion.choices[0]
        msg = choice.message
        tool_calls = msg.tool_calls or []

        # Append assistant turn to history
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
            # 2/N. FINAL RESPONSE — last evidence row
            record_evidence(
                db, tenant_id=TENANT_ID, invocation_id=inv_id,
                evidence_kind="response", role="assistant",
                payload={"content": msg.content or "",
                          "iterations": iterations,
                          "cost_usd": round(call_cost, 6)},
                correlation_id=corr_id,
            )
            evidence_rows_written += 1
            _row(f"iter {iterations}  - final response",
                 (msg.content or "")[:60] + "...")
            break

        # Execute each tool call + write 2 evidence rows (call + result)
        for tc in tool_calls:
            tool_name = tc.function.name
            try:
                args = json.loads(tc.function.arguments)
            except json.JSONDecodeError:
                args = {}

            # TOOL_CALL evidence row
            record_evidence(
                db, tenant_id=TENANT_ID, invocation_id=inv_id,
                evidence_kind="tool_call", role="assistant",
                payload={"tool_name": tool_name, "args": args,
                          "tool_call_id": tc.id},
                correlation_id=corr_id,
            )
            evidence_rows_written += 1

            # Run the actual Python tool
            tool_fn = _TOOLS_PYTHON.get(tool_name)
            if tool_fn is None:
                tool_result = {"error": f"unknown tool: {tool_name}"}
            else:
                try:
                    tool_result = tool_fn(**args)
                except Exception as exc:
                    tool_result = {"error": str(exc)}
            tool_calls_executed += 1

            # TOOL_RESULT evidence row
            record_evidence(
                db, tenant_id=TENANT_ID, invocation_id=inv_id,
                evidence_kind="tool_result", role="tool",
                payload={"tool_name": tool_name, "result": tool_result,
                          "tool_call_id": tc.id},
                correlation_id=corr_id,
            )
            evidence_rows_written += 1

            _row(f"iter {iterations}  - tool call",
                 f"{tool_name}({list(args.keys())}) -> "
                 f"{json.dumps(tool_result)[:50]}...")

            # Feed result back into conversation
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": json.dumps(tool_result),
            })

    return {
        "invocation_id": inv_id,
        "iterations": iterations,
        "tool_calls_executed": tool_calls_executed,
        "evidence_rows_written": evidence_rows_written,
        "total_cost_usd": total_cost_usd,
        "correlation_id": corr_id,
    }


# ── Orchestrator ────────────────────────────────────────────────────


def main() -> int:
    if not os.environ.get("OPENAI_API_KEY"):
        print("OPENAI_API_KEY not set. Skipping live test.")
        print("Set it in .env or environment and re-run.")
        return 0

    try:
        from openai import OpenAI  # noqa: F401
    except ImportError:
        print("openai package not installed.")
        return 0

    db, label, dispose = _open_session()
    print(f"\n*** Multi-step OpenAI e2e against {label.upper()} ***")
    try:
        init_storage(db)

        _hdr("PHASE 1  ·  Configure runtime budget cap")
        set_budget(
            db, tenant_id=None, scope="agent",
            scope_key=AGENT_DEF["agent_key"],
            window="1h", threshold_usd=0.05, hard_refuse=True,
            reason="$0.05/hour cap on the meeting agent",
        )
        _row("agent budget", "$0.05 / 1h  (hard refuse)")

        _hdr("PHASE 2  ·  Multi-step OpenAI agent loop")
        result = run_agent_loop(
            db,
            user_prompt=(
                "Schedule a 30-minute meeting with Bob at "
                "bob@example.com for tomorrow afternoon."
            ),
        )

        _hdr("PHASE 3  ·  Run summary")
        _row("iterations (LLM calls)", result["iterations"])
        _row("tool calls executed", result["tool_calls_executed"])
        _row("evidence rows written", result["evidence_rows_written"])
        _row("total LLM cost", f"${result['total_cost_usd']:.6f}")
        _check("evidence chain grew beyond a single prompt",
               result["evidence_rows_written"] >= 5,
               f"actual={result['evidence_rows_written']}")

        _hdr("PHASE 4  ·  Verify HMAC chain integrity")
        chain = verify_chain(db, tenant_id=TENANT_ID,
                              invocation_id=result["invocation_id"])
        _row("rows checked", chain.get("checked"))
        _row("valid", chain.get("valid"))
        _row("broken_at", chain.get("broken_at"))
        _check("chain verifies clean", chain.get("valid", False))

        _hdr("PHASE 5  ·  Per-invocation cost roll-up")
        from kya.cost_analytics import cost_per_invocation
        roll = cost_per_invocation(
            db, tenant_id=TENANT_ID, invocation_id=result["invocation_id"])
        for k, v in (roll or {}).items():
            _row(k, v)
        _check("cost-per-invocation aggregates the loop's events",
               roll is not None and roll["events"] >= result["iterations"])

        _hdr("E2E MULTI-STEP RUN PASSED")
        return 0
    finally:
        try:
            db.close()
        except Exception:
            pass
        dispose()


if __name__ == "__main__":
    sys.exit(main())
