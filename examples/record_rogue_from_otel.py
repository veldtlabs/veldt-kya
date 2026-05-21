"""Quick-start: record rogue agent signals from your own pipeline.

Use case: your agent middleware detects an out-of-scope tool call,
a cross-tenant access attempt, or a data leak. Tell kya so it shows
up in the agent's risk report.

Run:
    pip install veldt-kya
    python record_rogue_from_otel.py
"""

from kya import (
    get_rogue_signals,
    record_cross_tenant_attempt,
    record_oos_tool_attempt,
    rogue_score,
)

AGENT_KEY = "ops_assistant"
TENANT = "tenant_a3f"

# Agent tried a tool it isn't authorized for.
record_oos_tool_attempt(AGENT_KEY, tool="execute_sql", tenant_id=TENANT)

# Agent passed a different tenant_id than its caller's JWT.
record_cross_tenant_attempt(AGENT_KEY, expected_tid=TENANT, actual_tid="tenant_other")

# Read back the rolling rogue report.
report = get_rogue_signals(AGENT_KEY)
print(f"oos_tool_attempts:        {report.oos_tool_attempts}")
print(f"cross_tenant_attempts:    {report.cross_tenant_attempts}")
print(f"rogue_score (0..50):      {rogue_score(report)}")
