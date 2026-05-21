"""Quick-start: score a LangChain agent definition with kya.

Run:
    pip install veldt-kya
    python score_langchain_agent.py

No network, no DB. Pure-function risk scoring.
"""

from kya import bucket_for, normalize_agent_def, score_agent

# Replace with your real AgentExecutor — kya's normalize_agent_def reads
# .tools, .agent.llm, etc. via duck-typing; we use a dict shape here so
# the example runs without installing LangChain.
langchain_agent = {
    "agent_key": "ops_assistant",
    "name": "Ops Assistant",
    "agent": {"llm": {"model": "gpt-4o-mini"}},
    "tools": [
        {"name": "execute_sql", "description": "Run a read-only query"},
        {"name": "send_slack_message", "description": "Post to Slack"},
    ],
}

canonical = normalize_agent_def("langchain", langchain_agent)
score = score_agent(canonical)
print(f"score={score.score}  bucket={bucket_for(score.score)}")
for factor in score.factors:
    print(f"  {factor.delta:+4d}  {factor.name:30s}  {factor.label}")
