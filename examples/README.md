# KYA Examples

Runnable examples covering the full KYA surface. Most run with `pip install -e ".[all]"` plus the framework-specific extras called out per group. Cross-backend examples (`*_all_backends.py`) require local PostgreSQL + MySQL containers; everything else works against SQLite by default.

## Start here

| Example | What it shows |
|---|---|
| `sdk_smoke_test.py` | Minimal smoke test — `pip install veldt-kya` works, core SDK loads |
| `score_langchain_agent.py` | Score a single LangChain agent in ~20 lines — best first read |
| `benchmark_kya_latency.py` | Pure-function scorer latency (sub-millisecond at p99) |

## Composition algebra & policy primitives

| Example | What it shows |
|---|---|
| `three_channel_composition_witness.py` | **Lemma 1 (only-tighten) witness** — platform / tenant / signed-recommendation composition |
| `four_gate_adversarial_test.py` | Four-gate inbound apply pipeline under adversarial inputs |
| `interaction_multiplier_ablation.py` | The 10 named interaction multipliers, isolated per factor |
| `live_e2e_delegation_policy.py` | Per-dimension delegation ceiling (Liang-2025 topology defense) |
| `live_e2e_delegation_overrides.py` | How operators override delegation defaults |

## Framework adapters

| Example | Framework |
|---|---|
| `score_langchain_agent.py`, `live_langchain_clean.py`, `demo_langchain_handler.py` | LangChain |
| `live_openai_agents.py`, `live_e2e_openai_multistep.py` | OpenAI Agents SDK |
| `live_e2e_real_openai_plus_fiddler.py` | OpenAI + Fiddler bridge |
| `live_e2e_multiagent_fiddler.py` | Multi-agent CrewAI/Fiddler hybrid |
| `live_activegraph_with_kya.py` | ActiveGraph state runtime + KYA trust rail |
| `framework_integration_check.py` | Sanity probe across all 15+ adapters |

## Principals & identity (KYP)

| Example | What it shows |
|---|---|
| `demo_principals.py` | Unified KYP schema — users, agents, services in one model |
| `live_e2e_external_id_binding.py` | Bind external IDP subjects to KYP principals |
| `live_e2e_jwt_auth.py`, `live_e2e_real_jwt_idps.py` | JWT-based auth into KYP |
| `live_e2e_keycloak_real_idp.py` | Keycloak as identity provider |
| `live_e2e_spiffe.py`, `live_e2e_spiffe_real_jwt.py` | SPIFFE workload identity |
| `live_e2e_rbac.py` | Role-based access control gating tool calls |
| `live_e2e_min_trust_auto_block.py` | Auto-block actions when principal trust falls below threshold |
| `live_e2e_risk_tier_defaults.py` | Per-tier (low/medium/high/critical) default policies |

## Evidence, audit & regulator pack

| Example | What it shows |
|---|---|
| `demo_evidence.py` | HMAC-chained per-invocation evidence — write + verify |
| `live_e2e_audit_export.py` | Ed25519-signed audit export for regulators |
| `demo_event_vs_ingest_time.py` | Event-time vs ingest-time accounting in the chain |
| `kms_provider_example.py` | KMS-backed signing key provider (drop-in for cloud KMS) |
| `demo_regulator_pack.py`, `demo_regulator_pack_full_7_items.py` | Full regulator-grade evidence bundle (SR 11-7 / ISO 42001 / EU AI Act / etc.) |
| `demo_regulator_pack_all_backends.py` | Same, verified across PG / MySQL / SQLite / DuckDB |

## Red-teaming & adversarial

| Example | What it shows |
|---|---|
| `four_gate_adversarial_test.py` | Adversarial inputs probed against the four-gate apply pipeline |
| `live_e2e_attack_chains.py` | Multi-step attack-chain rule detection |
| `live_e2e_three_way_attacks.py` | Three-way attacker / target / KYA scenario |
| `live_e2e_hardening.py` | Hardening checks against common attack patterns |
| `redteam_cross_backend.py` | Red-team probe set, replicated across all storage backends |

## Multi-agent & orchestration

| Example | What it shows |
|---|---|
| `openclaw_e2e_multi_agent.py` | Multi-agent OpenCLAW orchestration end-to-end |
| `live_e2e_openclaw_full_orchestration.py` | Full orchestration with KYA trust rail |
| `live_e2e_openclaw_6agents_complex.py` | 6-agent complex topology |
| `live_e2e_three_way_openclaw.py`, `live_e2e_three_way_v2.py` | Three-way agent scenarios |
| `live_e2e_fanout_attribution.py` | Two-axis delegation attribution under multi-agent fan-out |
| `live_e2e_multiagent_multijudge.py` | Multi-agent + multi-judge consensus |

## Multi-judge orchestrator

| Example | What it shows |
|---|---|
| `live_e2e_multijudge_comparison.py` | Compare judges (OpenAI / heuristic / PyRIT / Presidio) on the same input |
| `live_e2e_fiddler_pure_standalone.py` | Fiddler bridge as a standalone judge |
| `framework_integration_check.py` | Confirms judges + adapters work together end-to-end |

## Observability bridges (OTel / OpenInference)

| Example | What it shows |
|---|---|
| `demo_hooks_wire_in.py` | Wire `kya_hooks` callbacks into your app code |
| `record_rogue_from_otel.py` | Convert OpenTelemetry spans into KYA rogue signals |
| `live_openinference_to_bridge.py` | OpenInference spans through the OTLP bridge |

## Cross-backend verification & load

| Example | What it shows |
|---|---|
| `verify_all_tables_all_backends.py` | All 17 KYA tables exist and write/read correctly on PG / MySQL / SQLite / DuckDB |
| `verify_tables_have_data.py` | Post-write sanity that rows actually landed |
| `verify_0_1_2_live_pg.py` | v0.1.2 verification suite against live PostgreSQL |
| `concurrency_load_test.py`, `concurrency_load_test_all_backends.py` | 20-worker concurrency, ~1,800 ops/sec sustained |
| `live_real_llm_all_backends.py` | Real LLM calls (OpenAI / Anthropic / Bedrock) on each backend |
| `demo_live_data.py`, `demo_live_data_mysql.py` | Live data ingestion examples per backend |

---

**Anything missing or unclear?** Open a [Discussion](https://github.com/veldtlabs/veldt-kya/discussions) or file a [feature request](https://github.com/veldtlabs/veldt-kya/issues/new?template=feature_request.md).

**Want to contribute an example?** See [CONTRIBUTING.md](../CONTRIBUTING.md) — short PRs adding examples are encouraged.
