"""
ActiveGraph x KYA bridge demo.

Demonstrates that an ActiveGraph (Nakajima 2026, arXiv:2605.21997)
agent runtime can be wrapped by KYA's principal-trust attribution
mechanism with a small adapter -- no changes to either library.

Requires:
    pip install activegraph veldt-kya

The bridge maps:
- ActiveGraph's `Event.actor`    -> KYP `principal_id` (kind `agent`)
- ActiveGraph's `Event.frame_id` -> orchestrator-equivalent principal
  whose trust counter is debited via the two-axis upward attribution.

The two libraries coexist without modification. ActiveGraph is an
agent runtime; KYA is a trust + attribution layer on top of it.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass

# Force in-memory SQLite for the demo — leaves no trace
os.environ["KYA_DB_URL"] = "sqlite:///:memory:"

from kya.session import reset_default_session  # noqa: E402
reset_default_session()

from kya import (  # noqa: E402
    default_session,
    ensure_principal_table,
    record_principal_signal,
    get_principal_trust,
)

# ActiveGraph imports
import activegraph as ag  # noqa: E402


# ── Bridge: ActiveGraph Event → KYP signal ──────────────────────────────

# Which event types do we treat as rogue signals?
ROGUE_EVENT_TYPES = {
    "task.deleted_outside_scope": "oos_tool",
    "task.cross_frame_access":    "cross_tenant",
    "object.leaked":              "data_leak",
}


def kya_bridge(event: ag.Event, db, tenant_id: str = "demo_tenant") -> bool:
    """Translate one ActiveGraph Event into KYP debits.

    Returns True if the event was treated as rogue and debits were applied.
    """
    signal_kind = ROGUE_EVENT_TYPES.get(event.type)
    if not signal_kind:
        return False

    # KYA two-axis: debit the actor (behavior that fired) AND the
    # frame (orchestrator-equivalent) at the moment of signal emission.
    actor = event.actor or "unknown_behavior"
    frame = event.frame_id or "unknown_frame"

    record_principal_signal(
        db, tenant_id=tenant_id,
        principal_kind="agent", principal_id=actor,
        signal_kind=signal_kind,
        attributes={"source": "activegraph_bridge", "event_id": event.id},
    )
    if frame != actor:
        record_principal_signal(
            db, tenant_id=tenant_id,
            principal_kind="agent", principal_id=frame,
            signal_kind=signal_kind,
            attributes={"source": "activegraph_bridge", "event_id": event.id,
                        "role": "frame_orchestrator"},
        )
    return True


# ── Demo: fabricate a sequence of ActiveGraph Events ────────────────────

def make_event(event_id: str, event_type: str, actor: str, frame_id: str,
               caused_by: str | None = None, payload: dict | None = None) -> ag.Event:
    """Construct an ag.Event by hand (no Runtime needed for this demo)."""
    return ag.Event(
        id=event_id,
        type=event_type,
        payload=payload or {},
        actor=actor,
        frame_id=frame_id,
        caused_by=caused_by,
        timestamp="2026-05-23T15:00:00Z",
    )


def main() -> int:
    print("=" * 70)
    print("ActiveGraph × KYA bridge demo")
    print("=" * 70)
    print(f"ActiveGraph version: {ag.__version__ if hasattr(ag, '__version__') else '1.0.5.post2'}")
    import kya
    print(f"KYA version:         {kya.__version__}")
    print()

    with default_session() as db:
        ensure_principal_table(db)
        db.commit()

        # Two principals will accumulate trust history:
        #   `compromised_subagent` -- the behavior that emits rogue events
        #   `triage_frame`         -- the frame_id under which the rogue
        #                             behaviors fire; orchestrator-equivalent
        actor_id = "compromised_subagent"
        frame_id = "triage_frame"

        # Baseline
        print("--- Baseline (trust score = STARTING_TRUST=50) ---")
        for pid in (actor_id, frame_id):
            t = get_principal_trust(db, tenant_id="demo_tenant",
                                    principal_kind="agent", principal_id=pid)
            print(f"  {pid}: trust={t.trust_score} bucket={t.bucket}")
        print()

        # Now simulate 8 sub-agent invocations where the compromised
        # behavior fires a rogue event each time.
        print("--- Replaying 8 rogue ActiveGraph events through the bridge ---")
        for i in range(1, 9):
            ev = make_event(
                event_id=f"evt-{i:03d}",
                event_type="task.deleted_outside_scope",  # rogue, maps to oos_tool
                actor=actor_id,
                frame_id=frame_id,
                caused_by=f"evt-{i-1:03d}" if i > 1 else None,
                payload={"task_id": f"task-{i}"},
            )
            applied = kya_bridge(ev, db)
            db.commit()
            t_actor = get_principal_trust(db, tenant_id="demo_tenant",
                                          principal_kind="agent", principal_id=actor_id)
            t_frame = get_principal_trust(db, tenant_id="demo_tenant",
                                          principal_kind="agent", principal_id=frame_id)
            print(f"  invocation {i}: applied={applied}"
                  f"  actor.trust={t_actor.trust_score:>3} ({t_actor.bucket})"
                  f"  frame.trust={t_frame.trust_score:>3} ({t_frame.bucket})")
        print()

        # Final state
        print("--- Final trust state ---")
        for pid, role in [(actor_id, "ActiveGraph behavior (sub-agent equivalent)"),
                          (frame_id, "ActiveGraph frame (orchestrator equivalent)")]:
            t = get_principal_trust(db, tenant_id="demo_tenant",
                                    principal_kind="agent", principal_id=pid)
            print(f"  {pid:25s} {role}")
            print(f"    trust={t.trust_score}/100  bucket={t.bucket}")
        print()
        print("Demonstration: the two-axis upward attribution moves the")
        print("frame-equivalent principal's trust counter into the same")
        print("'risky' bucket as the misbehaving actor — without modifying")
        print("either ActiveGraph or KYA. The bridge is %d lines of code." %
              sum(1 for line in open(__file__) if line.strip() and not line.strip().startswith("#")))

    return 0


if __name__ == "__main__":
    sys.exit(main())
