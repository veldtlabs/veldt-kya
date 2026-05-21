"""
Input source classification — where does this agent's data come from?

Two agents with identical tools can have very different risk profiles
depending on what they INGEST. An agent that processes only internal
database records is qualitatively safer than one that fetches arbitrary
URLs or accepts user-uploaded files. Untrusted inputs are the #1 vector
for prompt injection, data poisoning, and adversarial content.

Taxonomy
--------
    internal_database     — tenant-controlled DB (lowest risk)      (0)
    trusted_api           — internal API with contract              (0)
    streaming_event_bus   — Kafka/Pulsar/etc., producer-trusted     (2)
    user_prompt           — chat input from a user                  (5)
    public_dataset        — HF Hub, public Kaggle, etc.             (8)
    external_api          — third-party API, vendor-controlled      (8)
    web_fetch             — arbitrary URL fetch / scrape            (15)
    user_upload           — file uploaded by a user                 (15)
    unknown               — source not declared                     (10)

Why these weights
-----------------
- `web_fetch` and `user_upload` are tied at 15 because they're the two
  most common prompt-injection / data-poisoning vectors in 2025.
- `unknown` is heavier than `external_api` because at least with
  `external_api` you've declared the source intentionally.
- Internal sources score 0 — they're not free of risk, but the risk is
  expressed in OTHER dimensions (data_classes, security_caps).

Public API
----------
    INPUT_SOURCES                                    — known names
    SOURCE_WEIGHTS                                   — source → risk delta
    input_source_weight(sources: list[str]) -> int
    set_source_weights(weights)                      — runtime override
"""

INPUT_SOURCES = {
    "internal_database",
    "trusted_api",
    "streaming_event_bus",
    "user_prompt",
    "public_dataset",
    "external_api",
    "web_fetch",
    "user_upload",
    "unknown",
}

SOURCE_WEIGHTS = {
    "internal_database": 0,
    "trusted_api": 0,
    "streaming_event_bus": 2,
    "user_prompt": 5,
    "public_dataset": 8,
    "external_api": 8,
    "web_fetch": 15,
    "user_upload": 15,
    "unknown": 10,
}

# Cap on the input-source contribution — agents that touch multiple
# untrusted sources don't get triple-counted; the worst source dominates
# but we add a small premium for breadth.
SOURCE_CAP = 25


def set_source_weights(weights: dict, merge: bool = True) -> None:
    """Override input-source weights at runtime. `merge=False` replaces;
    `merge=True` (default) updates the table additively."""
    if not merge:
        SOURCE_WEIGHTS.clear()
    SOURCE_WEIGHTS.update(weights or {})


def input_source_weight(sources: list[str] | None) -> int:
    """Compute the input-source risk contribution.

    MAX(worst source weight) + small premium for additional untrusted
    sources beyond the first. Capped at SOURCE_CAP. Unknown source names
    are silently mapped to the "unknown" weight (NOT zero) — declaring
    something unrecognized is treated like not declaring at all.
    """
    if not sources:
        return SOURCE_WEIGHTS["unknown"]  # not declaring is a signal
    weights = [SOURCE_WEIGHTS.get(s, SOURCE_WEIGHTS["unknown"]) for s in sources]
    if not weights:
        return SOURCE_WEIGHTS["unknown"]
    base = max(weights)
    # Premium: +2 for each ADDITIONAL untrusted source (weight >= 5)
    extras = sum(1 for w in weights if w >= 5) - 1
    premium = max(0, extras * 2)
    return min(SOURCE_CAP, base + premium)
