"""End-to-end example: bind a DID-rooted principal into KYA.

Walks through:
  1. Configuring the DID adapter (env vars).
  2. Resolving a did:key URI to its DID document.
  3. (Optional) Verifying a JWT-VC the agent received from a trusted issuer.
  4. Binding the agent's principal to its DID.
  5. Reading back the binding through the existing lookup API.

Run with::

    KYA_DID_RESOLVERS=key,web,jwk python examples/live_e2e_did_principal.py

No network required — uses did:key which encodes the public key inline.
"""
from __future__ import annotations

import os

from kya import default_session, snapshot_agent
from kya.did import resolve_did
from kya.external_id import bind_did_principal, lookup_principal_by_idp


def main() -> None:
    # Step 0 — make sure the DID resolvers we plan to use are turned on.
    # The DID adapter is off by default to avoid surprises in existing
    # deployments; setting this env var opts in explicitly.
    os.environ.setdefault("KYA_DID_RESOLVERS", "key,web,jwk")

    # Step 1 — a real did:key URI (W3C Ed25519 test vector).
    agent_did = "did:key:z6MkrBdNdwUPnXDVD1DCxedzVVBpaGi8aSmoXFAeKNgtAer8"

    # Step 2 — resolve the DID. This validates the URI and gives us the
    # canonical document hash we can reference in audit records.
    doc = resolve_did(agent_did)
    print(f"Resolved {agent_did}")
    print(f"  document hash:  {doc.doc_hash[:16]}...")
    print(f"  key family:     {doc.verification_methods[0].public_key_jwk['crv']}")

    # Step 3 — register the agent inside KYA and bind its DID.
    tenant = "tenant-alpha"
    with default_session() as db:
        snapshot_agent(
            db,
            tenant_id=tenant,
            agent_key="planner_agent",
            definition={
                "agent_key": "planner_agent",
                "model": "openai/gpt-4o-mini",
                "tools": ["read_telemetry"],
                "human_loop": "in_the_loop",
                "access_level": "read",
                "data_classes": ["operational"],
                "compliance_scope": [],
            },
        )
        # The principal row must already exist for bind_did_principal to
        # succeed — snapshot_agent + a clean signal handle that. We need
        # a starting trust signal for the row to exist:
        from kya import record_principal_signal
        record_principal_signal(
            db,
            tenant_id=tenant,
            principal_kind="agent",
            principal_id="planner_agent",
            signal_kind="clean_invocation",
        )
        db.commit()

        ok = bind_did_principal(
            db,
            tenant_id=tenant,
            principal_kind="agent",
            principal_id="planner_agent",
            did=agent_did,
        )
        print(f"  bind ok:        {ok}")

        # Step 4 — read it back through the lookup path. The same
        # lookup function that handles OIDC and SPIFFE bindings works
        # for DIDs — no new query surface.
        found = lookup_principal_by_idp(
            db,
            tenant_id=tenant,
            idp_kind="did",
            idp_subject=agent_did,
        )
        print(f"  lookup result:  {found}")


if __name__ == "__main__":
    main()
