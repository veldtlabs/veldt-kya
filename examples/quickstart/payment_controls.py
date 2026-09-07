"""Payment controls for an agent that moves money.

Two limits, because one is not enough:
  * per payment  -- above it a human approves
  * per day      -- so an agent cannot simply split the payment up
"""
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

import kya
from kya.policy_evaluator import EvaluationInput, VerdictResult

AUTO_APPROVE = 1_000.00
DAILY_CAP = 2_500.00


def _approved_today(tenant_id: str, agent: str) -> float:
    """What KYA has already recorded this agent successfully moving."""
    since = datetime.now(timezone.utc) - timedelta(days=1)
    total = 0.0
    with kya.default_session() as db:
        rows = db.execute(text(
            "SELECT payload FROM kya_evidence "
            "WHERE tenant_id = :t AND evidence_kind = 'gateway_verdict' "
            "AND occurred_at >= :since"), {"t": tenant_id, "since": since})
        for (payload,) in rows:
            p = json.loads(payload) if isinstance(payload, str) else payload
            if p.get("verdict") != "allow" or p.get("external_subject") != agent:
                continue
            call = p.get("tool_call") or {}
            if call.get("name") == "transfer_funds":
                total += float(call.get("arguments", {}).get("amount") or 0)
    return total


class PaymentControls:
    name = "payment-controls"

    def evaluate(self, inp: EvaluationInput) -> VerdictResult:
        amount = float(inp.attributes.get("tool.input.amount") or 0)
        already = _approved_today(inp.tenant_id, inp.principal_id)

        # A payment waiting on a human has not been made, so it does
        # not consume the day's budget.
        if amount > AUTO_APPROVE:
            return VerdictResult(verdict="flag_for_review",
                                 reasons=("over_auto_approve_limit",))
        if already + amount > DAILY_CAP:
            return VerdictResult(verdict="deny",
                                 reasons=("daily_cap_exceeded",))
        return VerdictResult(verdict="allow")


kya.register_evaluator("payment-controls", PaymentControls())
