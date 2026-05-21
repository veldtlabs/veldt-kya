"""Phase-2 verification: confirm the v0.1 wheel ships `kya` + `kya_hooks`."""
import kya
import kya_hooks

print("Both core packages import OK from the installed wheel")
print("  kya.__version__         :", kya.__version__)
print("  kya_hooks.__version__   :", kya_hooks.__version__)

for name, obj in [
    ("kya.snapshot_agent", kya.snapshot_agent),
    ("kya.record_evidence", kya.record_evidence),
    ("kya.enable_inbound", kya.enable_inbound),
    ("kya.enable_dual_write", kya.enable_dual_write),
    ("kya.set_session_factory", kya.set_session_factory),
    ("kya_hooks.KyaClient", kya_hooks.KyaClient),
    ("kya_hooks.openai_agents_hooks", kya_hooks.openai_agents_hooks),
    ("kya_hooks.claude_agent_hooks", kya_hooks.claude_agent_hooks),
    ("kya_hooks.DataLeakScanner", kya_hooks.DataLeakScanner),
]:
    print(f"  {name:36s} : {bool(obj)}")
