# Quickstart

Every output block in the top-level README is produced by this directory.

```bash
pip install "veldt-kya[gateway,attack_chains]"
python run.py
```

`run.py` starts a throwaway gateway and a stub tool on localhost, runs all
six examples, prints what happened, and shuts both down. It writes only
`quickstart.db` and `executed.jsonl`, both inside this directory, and both
are recreated on every run.

| File | |
|---|---|
| `run.py` | Runs the six examples end to end |
| `serve.py` | Starts the gateway with the example evaluators registered |
| `backend.py` | Stand-in for the tool your agents call; records what it executed |
| `gateway.yaml` | Gateway config |
| `payment_controls.py` | Per-payment and per-day limits |
| `exfil_blocker.py` | Deny on a tool argument |
| `agent_identity.py` | Ed25519 -> did:jwk + proof-of-possession |

`gateway.yaml` sets `allow_header_trust: true` so the examples need no key
management. That accepts `X-KYA-DID` without proof, so any caller could claim
any identity — see the Identity section of the top-level README for the real
setup, which `agent_identity.py` implements.
