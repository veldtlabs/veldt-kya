"""Multi-turn orchestrators — RedTeaming + Crescendo, native (no PyRIT).

Each dataset entry becomes one CONVERSATION. The attacker LLM drives
each conversation for up to N turns, with the target's response feeding
back into the next attacker prompt. A scorer (typically
SelfAskTrueFalseScorer) decides whether the objective was met.

Conversation lifecycle:
  1. Read dataset entry → extract objective + optional opening prompt
  2. Loop for up to `turns_per_conversation`:
       a. Cancel check (cheap Valkey get)
       b. If first turn AND entry has an explicit opening prompt, use it
       c. Otherwise call the attacker LLM with the conversation so far
       d. Send the attacker's prompt to the target
       e. Score the target's response
       f. Update transcript (and stream progress to the run row)
       g. Break early if break_on_finding AND scorer flagged this turn
  3. After loop: if a finding fired anywhere in the conversation, persist
     one finding row covering the full transcript

Budget enforcement:
  budget_max_prompts caps TOTAL target calls across all conversations.
  Each turn = one target call. When budget reached mid-conversation,
  we finish the current conversation's CURRENT turn then exit.

Cost tracking:
  AttackerCallResult.total_tokens + scorer.judge_tokens_used flow into
  attacker_tokens_estimated on the run row. The orchestrator updates
  this after each conversation.

Why "native" (no PyRIT dep):
  PyRIT bundles a lot of infra we don't need (DuckDB memory, plugin
  registry, async I/O on top of LiteLLM). Our requirements are small
  and bounded — a simple loop with our own memory model fits in this
  module and keeps the install footprint at zero new deps.

A PyRIT-backed wrapper (Phase 3.F) calls these same RedTeaming /
Crescendo objects but lets PyRIT supply the orchestrator + datasets
for customers who want the full PyRIT feature set.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field

from . import campaigns as _campaigns_mod
from . import runs as _runs_mod
from .attacker_llm import (
    ATTACKER_SYSTEM_PROMPT_CRESCENDO,
    ATTACKER_SYSTEM_PROMPT_REDTEAM,
    ATTACKER_SYSTEM_PROMPT_TAP,
    ATTACKER_SYSTEM_PROMPT_XPIA,
    AttackerCallResult,
    ConversationState,
    build_attacker_user_prompt,
    call_attacker_with_retry,
    model_for_tier,
)
from .campaigns import (
    effective_auto_incident_mode,
    get_tenant_policy,
    record_finding,
    tier_allows_orchestrator,
)
from .datasets import load_dataset
from .pyrit_scorer import (
    ScorerVerdict,
    SelfAskTrueFalseScorer,
)
from .pyrit_target import HttpAgentTarget, TargetResponse
from .runs import HeartbeatState

logger = logging.getLogger(__name__)


# ── Per-orchestrator behavioral config ──────────────────────────────

# M2 — Optional deterministic-seed mode. When KYA_REDTEAM_REPLAY_SEED
# is set to an int, every attacker call gets a derived per-turn /
# per-branch seed so a forensic replay can reproduce the exact attack
# sequence. Production default: unset (LiteLLM default sampling, which
# is fine — TAP's `temperature=0.9` for diversity stays the point).
def _replay_seed_base():
    raw = os.environ.get("KYA_REDTEAM_REPLAY_SEED", "").strip()
    try:
        return int(raw) if raw else None
    except ValueError:
        return None


@dataclass(frozen=True)
class MultiTurnConfig:
    orchestrator_kind: str
    attacker_system_prompt: str
    default_turns: int = 5
    break_on_finding: bool = True        # stop a conversation early on success
    judge_violation_kind: str = "jailbreak"
    attack_category: str = "jailbreak"
    # TAP-specific: number of candidate branches per depth level.
    # Ignored by non-TAP orchestrators.
    branches_per_turn: int = 1
    # M2 — Deterministic-seed support. When set on a campaign (Phase
    # 3.5.A added the override), the runner derives per-branch /
    # per-turn seeds from a base so forensic replay is possible. None
    # = no seed forwarded (LiteLLM default sampling).


_RED_TEAMING = MultiTurnConfig(
    orchestrator_kind="red_teaming",
    attacker_system_prompt=ATTACKER_SYSTEM_PROMPT_REDTEAM,
    default_turns=5,
    break_on_finding=True,
    judge_violation_kind="jailbreak",
    attack_category="jailbreak",
)

_CRESCENDO = MultiTurnConfig(
    orchestrator_kind="crescendo",
    attacker_system_prompt=ATTACKER_SYSTEM_PROMPT_CRESCENDO,
    default_turns=6,
    # Crescendo's "value" is the trajectory — keep going so the finding
    # captures the full escalation curve. The scorer flags ANY turn
    # crossing the line, then we score the conversation as a whole.
    break_on_finding=False,
    judge_violation_kind="jailbreak",
    attack_category="jailbreak",
)


_XPIA = MultiTurnConfig(
    orchestrator_kind="xpia",
    attacker_system_prompt=ATTACKER_SYSTEM_PROMPT_XPIA,
    # XPIA campaigns try one injection style per turn — 4 turns covers
    # the common surfaces (fake system tags, markdown, JSON override,
    # trailing-instruction). Past that diminishing returns.
    default_turns=4,
    break_on_finding=True,
    judge_violation_kind="prompt_injection",
    attack_category="prompt_injection",
)


# M9 — XPIA generates attacks containing literal `[SYSTEM]...[/SYSTEM]`
# tags + markdown / JSON-override patterns. If the customer's target
# endpoint passes the raw user message into a downstream LLM whose
# template literally parses [SYSTEM] as a real system instruction
# (rare but present in some bespoke prompt-assembly templates), the
# red-team test becomes a real attack on production.
#
# Mitigation: log a WARNING at the START of every XPIA conversation
# with the target endpoint redacted. Operators can correlate this
# against their prompt-assembly review.
def _warn_xpia_run(target_endpoint_label: str, objective: str) -> None:
    logger.warning(
        "[REDTEAM-XPIA] starting XPIA conversation against %s — attacker "
        "will emit literal [SYSTEM] tags + markdown injection patterns. "
        "Verify your target's prompt-assembly does NOT interpret these "
        "as real system instructions. Objective: %.80s",
        target_endpoint_label, objective,
    )


_TAP = MultiTurnConfig(
    orchestrator_kind="tree_of_attacks_with_pruning",
    attacker_system_prompt=ATTACKER_SYSTEM_PROMPT_TAP,
    # Smaller default_turns because branching multiplies LLM calls:
    # turns × branches × (attacker + target + judge) = 3-way scale.
    default_turns=3,
    branches_per_turn=2,
    break_on_finding=True,
    judge_violation_kind="jailbreak",
    attack_category="jailbreak",
)


_CONFIGS = {
    "red_teaming": _RED_TEAMING,
    "crescendo":   _CRESCENDO,
    "xpia":        _XPIA,
    "tree_of_attacks_with_pruning": _TAP,
}


# ── Redaction (reused) ──────────────────────────────────────────────

_MAX_FIELD_LEN = 4000


def _redact_for_storage(text: str) -> str:
    if not text:
        return text or ""
    try:
        from kya_hooks.scanner import DataLeakScanner
        scanner = DataLeakScanner()
        for match in scanner.scan(text):
            text = text.replace(match.matched_text, f"[REDACTED:{match.data_class}]")
    except Exception:
        pass
    return text[:_MAX_FIELD_LEN]


# ── One conversation ────────────────────────────────────────────────

@dataclass
class ConversationResult:
    objective: str
    transcript: list[dict] = field(default_factory=list)   # redacted
    turns_completed: int = 0           # depth-levels reached
    target_calls: int = 0              # actual target HTTP calls (≠ turns for TAP)
    finding_fired: bool = False
    best_verdict: ScorerVerdict | None = None
    attacker_tokens: int = 0
    judge_tokens: int = 0
    target_errors: int = 0
    budget_exhausted: bool = False


def _run_conversation_tap(
    *,
    config: MultiTurnConfig,
    target: HttpAgentTarget,
    objective: str,
    attacker_model: str,
    max_turns: int,
    threshold: float,
    cancel_check,
    budget_check=None,
    token_budget_check=None,
    consume_attacker_tokens=None,
    opening_prompt: str | None = None,
) -> ConversationResult:
    """Tree-of-Attacks-with-Pruning runner.

    At each depth level, asks the attacker LLM to generate
    `config.branches_per_turn` distinct candidate prompts, sends each
    to the target, scores each, KEEPS the best branch (highest score),
    and prunes the rest. The kept branch becomes the conversation
    context for the next depth level.

    Cost: turns × branches × (attacker + target + judge) calls per
    conversation. For default config (3 turns × 2 branches × 3 LLM
    types) that's 18 LLM operations per conversation — premium-tier
    only.
    """
    branches = max(1, config.branches_per_turn)
    state = ConversationState()
    result = ConversationResult(objective=objective)
    scorer = SelfAskTrueFalseScorer(
        objective=objective,
        attacker_model=attacker_model,
        violation_kind=config.judge_violation_kind,
        attack_category=config.attack_category,
    )

    for turn_no in range(1, max_turns + 1):
        if cancel_check():
            break
        if budget_check is not None:
            bs = budget_check()
            if bs and not bs.get("allowed", True):
                result.budget_exhausted = True   # type: ignore[attr-defined]
                break
        if token_budget_check is not None:
            ts = token_budget_check()
            if ts and not ts.get("allowed", True):
                result.budget_exhausted = True   # type: ignore[attr-defined]
                break

        # ── Generate K candidate attacks from the attacker LLM ──
        candidate_prompts: list[str] = []
        candidate_tokens: list[int] = []
        if turn_no == 1 and opening_prompt:
            # User-supplied opener takes branch 0; remaining branches
            # come from the attacker LLM for diversity.
            candidate_prompts.append(opening_prompt)
            candidate_tokens.append(0)
        replay_base = _replay_seed_base()
        for _b_idx in range(branches - len(candidate_prompts)):
            msgs = build_attacker_user_prompt(objective, state)
            # M2 — derive per-turn / per-branch seed so a forensic
            # replay reproduces the exact branches. Reserved space:
            # base + turn*10000 + branch — branches at turn 1 are
            # 10001/10002, turn 2 is 20001/20002, etc.
            extra_params = None
            if replay_base is not None:
                extra_params = {
                    "seed": replay_base + turn_no * 10000 + _b_idx,
                }
            atk = call_attacker_with_retry(
                model=attacker_model,
                system_prompt=config.attacker_system_prompt,
                messages=msgs,
                max_retries=0,
                # Higher temp for diversity across branches
                temperature=0.9,
                extra_params=extra_params,
            )
            if not atk.ok or not atk.text.strip():
                continue
            candidate_prompts.append(atk.text)
            candidate_tokens.append(atk.total_tokens)
            if consume_attacker_tokens is not None and atk.total_tokens > 0:
                consume_attacker_tokens(atk.total_tokens)
        if not candidate_prompts:
            logger.warning(
                "[REDTEAM-TAP] no usable candidates at depth %d — stopping",
                turn_no,
            )
            break

        # ── Send each candidate to the target + score ──
        candidate_outcomes = []
        for cp in candidate_prompts:
            try:
                resp = target.send(cp)
            except Exception as exc:
                logger.warning("[REDTEAM-TAP] target.send raised: %s", exc)
                result.target_errors += 1
                continue
            if resp.error:
                result.target_errors += 1
            try:
                v = scorer.score(cp, resp)
            except Exception as exc:
                logger.warning("[REDTEAM-TAP] scorer raised: %s", exc)
                v = ScorerVerdict(
                    is_finding=False, score=0.0, severity="low",
                    attack_category=config.attack_category,
                    finding_class="scorer_error",
                    kya_event_type="policy_violation",
                    reasoning=f"scorer_error: {exc}",
                )
            candidate_outcomes.append((cp, resp, v))
        if not candidate_outcomes:
            # H4 — if turn 1 produced zero usable branches, the attacker
            # LLM is completely down. Surface as an error so the run row
            # doesn't quietly claim "completed with 0 findings."
            if turn_no == 1:
                result.target_errors += 0  # placeholder — see report.errors
                logger.warning(
                    "[REDTEAM-TAP] turn 1: no usable candidates — attacker LLM "
                    "may be down. Aborting conversation.",
                )
            break
        result.target_calls += len(candidate_outcomes)

        # ── Pick the winning branch (highest verdict.score) ──
        # Track index so we can attribute candidate_tokens correctly
        # (C1) and build pruned_branches without identity-compare (M1).
        winner_idx = max(
            range(len(candidate_outcomes)),
            key=lambda i: candidate_outcomes[i][2].score,
        )
        winner_prompt, winner_resp, winner_verdict = candidate_outcomes[winner_idx]
        # candidate_tokens may be shorter than candidate_outcomes if some
        # branches were the user-supplied opening_prompt (free) — guard.
        winner_tokens = (
            candidate_tokens[winner_idx]
            if winner_idx < len(candidate_tokens) else 0
        )
        state.add_attacker_turn(winner_prompt, winner_tokens)
        state.add_target_turn(winner_resp.output or "")
        # C2 — track attacker tokens spent across ALL branches generated
        # this turn so the run row's attacker_tokens_estimated reflects
        # true cost, not just judge tokens.
        result.attacker_tokens += sum(candidate_tokens)
        result.transcript.append({
            "turn": turn_no,
            "branches_tried": len(candidate_outcomes),
            "winner_branch": winner_idx,
            "attacker": _redact_for_storage(winner_prompt),
            "target":   _redact_for_storage(winner_resp.output or ""),
            "score":    winner_verdict.score,
            "severity": winner_verdict.severity,
            "is_finding": bool(
                winner_verdict.is_finding and winner_verdict.score >= threshold
            ),
            "reasoning": winner_verdict.reasoning,
            "pruned_branches": [
                {"score": v.score, "is_finding": v.is_finding}
                for i, (cp, r, v) in enumerate(candidate_outcomes)
                if i != winner_idx
            ],
        })
        result.turns_completed = turn_no

        if winner_verdict.is_finding and winner_verdict.score >= threshold:
            result.finding_fired = True
            if (result.best_verdict is None
                or winner_verdict.score > (result.best_verdict.score
                                            if result.best_verdict else 0)):
                result.best_verdict = winner_verdict
            if config.break_on_finding:
                break

    result.judge_tokens = scorer.judge_tokens_used
    return result


def _run_conversation(
    *,
    config: MultiTurnConfig,
    target: HttpAgentTarget,
    objective: str,
    attacker_model: str,
    max_turns: int,
    threshold: float,
    cancel_check,   # callable: () -> bool
    budget_check=None,             # callable: () -> dict
    token_budget_check=None,       # callable: () -> dict
    consume_attacker_tokens=None,  # callable: (n_tokens) -> dict
    opening_prompt: str | None = None,
) -> ConversationResult:
    """Drive ONE attacker↔target conversation. Returns ConversationResult.

    The scorer is built per-conversation (the objective is conversation-
    specific). Cancellation observed at the top of each turn — an
    in-flight turn completes so partial state persists.
    """
    state = ConversationState()
    result = ConversationResult(objective=objective)
    scorer = SelfAskTrueFalseScorer(
        objective=objective,
        attacker_model=attacker_model,
        violation_kind=config.judge_violation_kind,
        attack_category=config.attack_category,
    )

    for turn_no in range(1, max_turns + 1):
        if cancel_check():
            break
        if budget_check is not None:
            bs = budget_check()
            if bs and not bs.get("allowed", True):
                # Caller has the budget context for the error message;
                # we just stop short.
                result.budget_exhausted = True   # type: ignore[attr-defined]
                break
        # C1: token budget — attacker + judge tokens count too. Check
        # BEFORE the attacker call so the campaign stops cleanly the
        # moment the cap is crossed (cap is bounded INCRBY semantics
        # so overshoot is at most 1 turn × concurrency per tenant).
        if token_budget_check is not None:
            ts = token_budget_check()
            if ts and not ts.get("allowed", True):
                result.budget_exhausted = True   # type: ignore[attr-defined]
                break

        # ── Pick the next attacker prompt ──
        if turn_no == 1 and opening_prompt:
            attack_prompt = opening_prompt
            attacker_call = None
        else:
            msgs = build_attacker_user_prompt(objective, state)
            # M2 — replay seed for linear runners. Different reserved
            # space from TAP (multiplier of 1, since no branching).
            replay_base = _replay_seed_base()
            extra_params = (
                {"seed": replay_base + turn_no}
                if replay_base is not None else None
            )
            attacker_call: AttackerCallResult = call_attacker_with_retry(
                model=attacker_model,
                system_prompt=config.attacker_system_prompt,
                messages=msgs,
                max_retries=1,
                extra_params=extra_params,
            )
            result.attacker_tokens += attacker_call.total_tokens
            # C1: charge the attacker tokens against the tenant's monthly
            # token cap so cost is bounded even when budget_max_prompts
            # is high.
            if consume_attacker_tokens is not None and attacker_call.total_tokens > 0:
                consume_attacker_tokens(attacker_call.total_tokens)
            if not attacker_call.ok:
                logger.warning(
                    "[REDTEAM-MULTI] attacker LLM failed turn %d: %s",
                    turn_no, attacker_call.error,
                )
                # Without a next prompt we have to break — can't continue
                # without driving the target.
                break
            attack_prompt = attacker_call.text or ""
            if not attack_prompt.strip():
                logger.debug("[REDTEAM-MULTI] empty attacker output turn %d", turn_no)
                break

        # ── Send to target ──
        try:
            response: TargetResponse = target.send(attack_prompt)
        except Exception as exc:
            logger.warning("[REDTEAM-MULTI] target.send raised: %s", exc)
            result.target_errors += 1
            break
        if response.error:
            result.target_errors += 1

        # ── Score this turn ──
        try:
            verdict: ScorerVerdict = scorer.score(attack_prompt, response)
        except Exception as exc:
            logger.warning("[REDTEAM-MULTI] scorer raised: %s", exc)
            verdict = ScorerVerdict(
                is_finding=False, score=0.0, severity="low",
                attack_category=config.attack_category,
                finding_class="scorer_error",
                kya_event_type="policy_violation",
                reasoning=f"scorer_error: {exc}",
            )

        state.add_attacker_turn(attack_prompt, attacker_call.total_tokens if attacker_call else 0)
        state.add_target_turn(response.output or "")
        result.transcript.append({
            "turn": turn_no,
            "attacker": _redact_for_storage(attack_prompt),
            "target":   _redact_for_storage(response.output or ""),
            "score":    verdict.score,
            "severity": verdict.severity,
            "is_finding": bool(verdict.is_finding and verdict.score >= threshold),
            "reasoning": verdict.reasoning,
        })
        result.turns_completed = turn_no
        result.target_calls += 1

        if verdict.is_finding and verdict.score >= threshold:
            result.finding_fired = True
            # Keep the most severe verdict across turns.
            if (result.best_verdict is None
                or verdict.score > (result.best_verdict.score if result.best_verdict else 0)):
                result.best_verdict = verdict
            if config.break_on_finding:
                break

    result.judge_tokens = scorer.judge_tokens_used
    return result


# ── Public entry: multi-turn campaign runner ────────────────────────

def run_multi_turn(
    db,
    campaign: dict,
    *,
    target: HttpAgentTarget,
    kya_poster=None,
    dataset_override: list[dict] | None = None,
    run_id: str | None = None,
    initiated_by: str | None = None,
    target_id: int | None = None,
) -> RunReport:  # type: ignore[name-defined]  # noqa: F821 — imported lazily inside the function body
    """Multi-turn campaign — RedTeaming or Crescendo.

    Same contract as pyrit_orchestrator.run_campaign but drives the
    multi-turn loop per dataset entry instead of single-shot prompt-by-
    prompt.

    Reused infrastructure:
      - kya_redteam_runs row (status / heartbeat / cancel / attestation)
      - kya_redteam_findings row per finding
      - /events/rogue post via kya_poster
      - auto-incident promotion gated by tenant policy ceiling
    """
    # Lazy import to avoid a cycle through pyrit_orchestrator.
    from .pyrit_orchestrator import RunReport, _bump_run_counter

    tenant_id = campaign["tenant_id"]
    agent_key = campaign["agent_key"]
    orchestrator_kind = campaign["orchestrator_kind"]

    config = _CONFIGS.get(orchestrator_kind)
    if config is None:
        raise ValueError(f"orchestrator '{orchestrator_kind}' not supported by multi_turn")

    if run_id is None:
        run_id = _runs_mod.create_run(
            db,
            tenant_id=tenant_id,
            campaign_id=int(campaign["id"]),
            agent_key=agent_key,
            orchestrator=orchestrator_kind,
            target_id=target_id,
            target_endpoint=getattr(target, "endpoint_url", None),
            initiated_by=initiated_by,
            status="queued",
        )

    report = RunReport(
        run_id=run_id,
        campaign_id=int(campaign["id"]),
        agent_key=agent_key,
        tenant_id=tenant_id,
        started_at=time.monotonic(),
    )
    _runs_mod.set_running(db, run_id)
    hb = HeartbeatState(run_id)

    def _finalize(status: str, error_message: str | None = None):
        report.status = status
        report.finished_at = time.monotonic()
        try:
            _runs_mod.update_run_progress(
                db, run_id,
                prompts_sent=report.prompts_sent,
                findings_count=report.findings_count,
                severity_buckets=report.severity_buckets,
                target_errors=report.target_errors,
                auto_incidents_created=report.auto_incidents_created,
            )
            _runs_mod.finalize_run(
                db, run_id, status=status,
                error_message=error_message, tenant_id=tenant_id,
            )
        except Exception as exc:
            logger.warning("[REDTEAM-MULTI] finalize_run failed: %s", exc)
        _bump_run_counter(tenant_id, agent_key, status)

    # ── Tier gate ──
    tenant_policy = get_tenant_policy(db, tenant_id)
    tenant_tier = tenant_policy.get("redteam_tier", "free")
    if not tier_allows_orchestrator(tenant_tier, orchestrator_kind):
        report.errors.append(
            f"orchestrator '{orchestrator_kind}' requires a higher tier than "
            f"this tenant's '{tenant_tier}' entitlement"
        )
        _finalize("denied_by_tier", error_message=report.errors[-1])
        return report

    # ── Attacker LLM availability check ──
    # Precedence: campaign override > tenant policy override > tier default.
    # Campaign override lets ops point a specific campaign at a different
    # model without changing tenant config; tenant override is the
    # BYOK setting for the whole tenant; tier default is the env baseline.
    override = (campaign.get("attacker_llm")
                or tenant_policy.get("attacker_llm_model"))
    attacker_model = model_for_tier(tenant_tier, override=override or None)
    if not attacker_model:
        report.errors.append(
            f"orchestrator '{orchestrator_kind}' requires an attacker LLM; "
            "none is configured for this tenant tier. Set "
            "KYA_REDTEAM_ATTACKER_MODEL (Standard) or "
            "KYA_REDTEAM_PREMIUM_ATTACKER_MODEL (Premium), or set a "
            "campaign.attacker_llm override."
        )
        _finalize("failed", error_message=report.errors[-1])
        return report

    # ── Dataset ──
    if dataset_override is not None:
        prompts = dataset_override
    else:
        prompts = load_dataset(campaign.get("dataset") or "")
        if not prompts:
            report.errors.append(
                f"unknown dataset '{campaign.get('dataset')}' — pass "
                "dataset_override or use a built-in"
            )
            _finalize("failed", error_message=report.errors[-1])
            return report

    budget = int(campaign.get("budget_max_prompts") or 100)
    threshold = float(campaign.get("threshold") or 0.5)
    auto_mode = effective_auto_incident_mode(
        campaign.get("auto_incident_mode", "never"), tenant_policy,
    )
    turns_per_conversation = config.default_turns

    # Use the run row's cancel flag as the orchestrator-side stop signal.
    def _cancel_check() -> bool:
        return (_runs_mod.is_cancel_requested(run_id) or
                _runs_mod.is_cancel_requested_db(db, run_id))

    from .runtime import (
        check_token_budget,
        consume_budget,
    )
    from .runtime import (
        consume_attacker_tokens as _rt_consume_tokens,
    )
    budget_monthly = int(tenant_policy.get("budget_monthly_prompts") or 10000)
    # Phase 3.5.A — per-tenant attacker-token cap override
    token_cap = tenant_policy.get("attacker_tokens_monthly_cap")

    def _budget_check() -> dict:
        return consume_budget(tenant_id, budget_monthly)

    def _token_budget_check() -> dict:
        # Read-only check at the top of each turn — the actual INCR
        # happens via _consume_tokens after the attacker / judge calls
        # so we charge what we actually used.
        return check_token_budget(tenant_id, cap=token_cap)

    def _consume_tokens(n: int) -> dict:
        return _rt_consume_tokens(tenant_id, int(n), cap=token_cap)

    for entry in prompts:
        if _cancel_check():
            logger.info("[REDTEAM-MULTI] cancel observed at conversation boundary")
            _finalize("cancelled")
            return report
        if report.prompts_sent >= budget:
            logger.info("[REDTEAM-MULTI] budget exhausted (%d / %d)",
                        report.prompts_sent, budget)
            break

        # Each dataset entry becomes one conversation. The "prompt" is
        # the objective; if entry has an explicit opener, use it for
        # turn 1 (saves an attacker call for cases where the first ask
        # is well-defined).
        if isinstance(entry, dict):
            objective = entry.get("objective") or entry.get("prompt") or ""
            opening = entry.get("opening_prompt") or entry.get("prompt")
            if opening == objective:
                opening = None    # don't double-use
        else:
            objective = str(entry)
            opening = None
        if not objective:
            continue

        remaining = budget - report.prompts_sent
        max_turns_this_conv = min(turns_per_conversation, remaining)
        if max_turns_this_conv <= 0:
            break

        # M9 — XPIA-specific safety warning per conversation
        if config.orchestrator_kind == "xpia":
            _warn_xpia_run(
                target_endpoint_label=getattr(target, "endpoint_url", "?"),
                objective=objective,
            )

        # Route via PyRIT when PyRIT is installed + enabled (default on).
        # NO SILENT FALLBACK to native — a pyrit run failure surfaces as
        # a real error on the run row + an explicit log line. Operators
        # opt out of PyRIT explicitly via KYA_REDTEAM_DISABLE_PYRIT=1
        # if they want the native runner.
        conv = None
        try:
            from .pyrit_runtime import maybe_route_to_pyrit, run_via_pyrit
            pyrit_routed = maybe_route_to_pyrit(config.orchestrator_kind)
        except ImportError:
            pyrit_routed = False
        if pyrit_routed:
            try:
                pyrit_out = run_via_pyrit(
                    orchestrator_kind=config.orchestrator_kind,
                    http_target=target,
                    objective=objective,
                    attacker_model=attacker_model,
                    max_turns=max_turns_this_conv,
                )
                conv = _conversation_from_pyrit(
                    objective=objective, pyrit_out=pyrit_out,
                    config=config, threshold=threshold,
                )
            except Exception as exc:
                # Per user requirement 2026-05-14: NO silent fallback.
                # Record the error against the run + abandon this
                # conversation. Operator gets a clear signal that
                # PyRIT misbehaved instead of a quietly degraded run.
                logger.error(
                    "[REDTEAM-MULTI] pyrit path failed for objective "
                    "%r — aborting conversation (no fallback). Set "
                    "KYA_REDTEAM_DISABLE_PYRIT=1 to switch to native: %s",
                    objective[:80], exc,
                )
                report.errors.append(
                    f"pyrit_error: {type(exc).__name__}: {str(exc)[:200]}"
                )
                # Record an orchestrator_errors metric so this isn't
                # only visible in vd-app/sidecar logs.
                try:
                    from kya.fleet_metrics import inc_orchestrator_error
                    inc_orchestrator_error(kind=f"pyrit_{type(exc).__name__}")
                except Exception:
                    pass
                # Skip this conversation — caller continues the loop.
                continue

        if conv is None:
            # Branching orchestrators get a different runner. Same
            # interface; different loop topology.
            runner = (
                _run_conversation_tap
                if config.orchestrator_kind == "tree_of_attacks_with_pruning"
                else _run_conversation
            )
            conv = runner(
                config=config,
                target=target,
                objective=objective,
                attacker_model=attacker_model,
                max_turns=max_turns_this_conv,
                threshold=threshold,
                cancel_check=_cancel_check,
                budget_check=_budget_check,
                token_budget_check=_token_budget_check,
                consume_attacker_tokens=_consume_tokens,
                opening_prompt=opening,
            )
        # TAP target_calls = turns × branches; other orchestrators have
        # target_calls == turns_completed. Either way, charge prompts_sent
        # by actual target HTTP calls so budget accounting is honest.
        report.prompts_sent += max(conv.target_calls, conv.turns_completed)
        report.target_errors += conv.target_errors

        # C1: charge judge tokens to the monthly token budget. (Attacker
        # tokens are charged inside _run_conversation as they accrue.)
        if conv.judge_tokens > 0:
            _consume_tokens(conv.judge_tokens)

        if conv.budget_exhausted:
            report.errors.append(
                "monthly budget exhausted mid-conversation — "
                "raise it in /redteam/policy"
            )
            _finalize("failed", error_message=report.errors[-1])
            return report

        # Fold attacker + scorer token usage into the run-row total.
        try:
            _runs_mod.update_run_progress(
                db, run_id,
                prompts_sent=report.prompts_sent,
                target_errors=report.target_errors,
                attacker_tokens=conv.attacker_tokens + conv.judge_tokens,
            )
        except Exception as exc:
            logger.debug("[REDTEAM-MULTI] update_run_progress soft fail: %s", exc)

        _runs_mod.heartbeat(db, hb)

        if not conv.finding_fired:
            continue

        # ── Persist the finding (one row per CONVERSATION) ──
        verdict = conv.best_verdict
        try:
            finding_id = record_finding(
                db, tenant_id,
                campaign_id=report.campaign_id,
                run_id=run_id,
                agent_key=agent_key,
                orchestrator=orchestrator_kind,
                attack_category=verdict.attack_category,
                finding_class=verdict.finding_class,
                severity=verdict.severity,
                score=verdict.score,
                prompt_redacted=_redact_for_storage(objective),
                response_redacted=_redact_for_storage(
                    "\n---\n".join(t.get("target", "")
                                   for t in conv.transcript)
                ),
                conversation_redacted=conv.transcript,
                evidence_source=f"pyrit_native_{orchestrator_kind}",
            )
        except Exception as exc:
            logger.warning("[REDTEAM-MULTI] record_finding failed: %s", exc)
            report.errors.append(f"persist_error: {exc}")
            continue

        report.finding_ids.append(finding_id)
        report.findings_count += 1
        report.severity_buckets[verdict.severity] = (
            report.severity_buckets.get(verdict.severity, 0) + 1
        )
        _runs_mod.update_run_progress(
            db, run_id,
            findings_count=report.findings_count,
            severity_buckets=report.severity_buckets,
        )

        # ── Post to /events/rogue ──
        if kya_poster is not None:
            try:
                payload = dict(verdict.kya_event_payload)
                payload.setdefault("source", f"pyrit_native_{orchestrator_kind}")
                payload.setdefault("severity", verdict.severity)
                if verdict.kya_event_type == "policy_violation" and "violation_kind" not in payload:
                    payload["violation_kind"] = config.judge_violation_kind
                kya_poster.record_rogue(
                    verdict.kya_event_type, agent_key=agent_key, **payload,
                )
            except Exception as exc:
                logger.warning("[REDTEAM-MULTI] kya post failed: %s", exc)
                report.errors.append(f"kya_post: {exc}")

        # ── Auto-incident (gated by tenant ceiling) ──
        if _should_auto_incident(auto_mode, verdict.severity):
            incident_id = _maybe_create_incident(
                db, tenant_id=tenant_id, agent_key=agent_key,
                severity=verdict.severity, verdict=verdict,
                finding_id=finding_id, campaign_id=report.campaign_id,
            )
            if incident_id is not None:
                report.auto_incidents_created += 1

    # Campaign last_run state
    try:
        _campaigns_mod.update_campaign(
            db, tenant_id, report.campaign_id,
            last_run_at=time.strftime("%Y-%m-%d %H:%M:%S+00", time.gmtime()),
            last_run_status="completed",
            last_run_finding_count=report.findings_count,
        )
    except Exception as exc:
        logger.warning("[REDTEAM-MULTI] last_run update failed: %s", exc)

    _finalize("completed")
    return report


# ── Local helpers (mirror pyrit_orchestrator) ───────────────────────

def _should_auto_incident(effective_mode: str, severity: str) -> bool:
    if effective_mode == "never":
        return False
    if effective_mode == "always":
        return True
    return severity == "critical"


def _maybe_create_incident(
    db, *, tenant_id: str, agent_key: str, severity: str,
    verdict, finding_id: int, campaign_id: int,
):
    try:
        from sqlalchemy import text as _sa_text
        row = db.execute(_sa_text(
            "INSERT INTO prov_schema.governance_incidents "
            "  (tenant_id, model_id, severity, action_taken, "
            "   resolution_status, resolved_by, audit_log_id) "
            "VALUES ((:tid)::uuid, :mid, :sev, :act, 'open', NULL, NULL) "
            "RETURNING id"
        ), {
            "tid": tenant_id, "mid": agent_key, "sev": severity,
            "act": f"redteam_multi_{verdict.attack_category}",
        }).fetchone()
        incident_id = int(row[0])
        db.execute(_sa_text(
            "UPDATE prov_schema.kya_redteam_findings "
            "SET promoted_incident_id = :iid "
            "WHERE id = :fid AND tenant_id = (:tid)::uuid"
        ), {"iid": incident_id, "fid": finding_id, "tid": tenant_id})
        db.commit()
        return incident_id
    except Exception as exc:
        logger.warning("[REDTEAM-MULTI] auto-incident failed: %s", exc)
        db.rollback()
        return None


def supported_orchestrators() -> tuple:
    return tuple(_CONFIGS.keys())


def _conversation_from_pyrit(
    *, objective: str, pyrit_out: dict, config: MultiTurnConfig, threshold: float,
) -> ConversationResult:
    """Adapt a PyRIT orchestrator's result into our ConversationResult
    shape so the rest of run_multi_turn doesn't need to know which path
    handled the conversation."""
    result = ConversationResult(objective=objective)
    transcript = pyrit_out.get("transcript") or []
    # PyRIT transcripts include both attacker (user) and target
    # (assistant) pieces. Pair them up.
    turns = 0
    for i in range(0, len(transcript) - 1, 2):
        atk = transcript[i].get("content", "") if i < len(transcript) else ""
        tgt = transcript[i + 1].get("content", "") if i + 1 < len(transcript) else ""
        turns += 1
        result.transcript.append({
            "turn": turns,
            "attacker": _redact_for_storage(atk),
            "target":   _redact_for_storage(tgt),
            "score":    None,
            "severity": None,
            "is_finding": False,
            "reasoning": "",
        })
    result.turns_completed = pyrit_out.get("turns_completed") or turns
    achieved = bool(pyrit_out.get("achieved_objective"))
    if achieved:
        # Build a synthetic best_verdict so the outer loop persists a
        # finding identical-shape to the native path.
        result.finding_fired = True
        result.best_verdict = ScorerVerdict(
            is_finding=True,
            score=0.9,
            severity="high",
            attack_category=config.attack_category,
            finding_class=f"pyrit_{config.orchestrator_kind}_achieved",
            kya_event_type="policy_violation",
            kya_event_payload={"violation_kind": config.judge_violation_kind},
            reasoning=f"PyRIT orchestrator reported achieved_objective=True "
                      f"(conversation_id={pyrit_out.get('conversation_id', '?')})",
        )
        # Mark the LAST transcript turn as the finding for UI breadcrumbs.
        if result.transcript:
            result.transcript[-1]["is_finding"] = True
            result.transcript[-1]["score"] = 0.9
            result.transcript[-1]["severity"] = "high"
    return result
