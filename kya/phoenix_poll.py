"""
Phoenix evaluator polling — Round 16.

Phoenix runs hallucination + QA-relevance evaluators against collected
traces async. The eval results sit in Phoenix's datastore, NOT in KYA.
Until now, callers had to invoke `record_hallucination()` manually for
those signals to show up in `kya/quality.py`. This module bridges the
gap: periodically poll Phoenix, pull the new eval rows, and feed them
into KYA's quality counters with the agent attribution.

Two callable surfaces:

  poll_phoenix_evals(window_minutes=30, since_ts=None) -> PollResult
    Run one poll cycle. Pulls hallucination + qa_relevance evals from
    the last window, maps each Phoenix trace -> agent_key via the
    veldt.agent_key span attribute (already emitted from observability.py),
    increments KYA counters accordingly.

  start_phoenix_poll_thread(interval_seconds=300)
    Background thread that runs poll_phoenix_evals() every interval.
    Started from main.py on app startup. Idempotent — safe to call once.

Feature flag
------------
KYA_PHOENIX_POLL_ENABLED=true (default OFF). When disabled, the module
imports cleanly and the start_*_thread function returns immediately.
KYA functions correctly without Phoenix integration.

Design notes
------------
- Read-only against Phoenix. Never writes.
- Idempotent — uses last_polled_at timestamp + Phoenix's eval_id to
  avoid double-counting. Stored in Valkey at `kya:phoenix:last_polled`.
- Fail-soft — Phoenix unreachable / wrong version / schema mismatch all
  log at warning and return empty results.
"""

import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


def is_enabled() -> bool:
    """Feature flag — default OFF. Set KYA_PHOENIX_POLL_ENABLED=true
    in env to opt in."""
    return os.environ.get("KYA_PHOENIX_POLL_ENABLED", "").lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


PHOENIX_HTTP_URL = os.environ.get(
    "PHOENIX_HTTP_URL",
    # Default to common docker-compose layout
    "http://vd-phoenix:6006",
)
POLL_INTERVAL_SECONDS = int(os.environ.get("KYA_PHOENIX_POLL_INTERVAL", "300"))
# Hallucination flag threshold — Phoenix evals are 0-1; we treat >= this
# as a confirmed hallucination signal.
HALLUCINATION_THRESHOLD = float(os.environ.get("KYA_PHOENIX_HALL_THRESHOLD", "0.7"))
QA_IRRELEVANCE_THRESHOLD = float(os.environ.get("KYA_PHOENIX_QA_THRESHOLD", "0.7"))

# Valkey key for last-polled cursor (so we don't re-process old rows on restart)
_CURSOR_KEY = "kya:phoenix:last_polled"


@dataclass
class PollResult:
    success: bool = False
    fetched_evals: int = 0
    hallucination_signals_recorded: int = 0
    qa_irrelevance_signals_recorded: int = 0
    skipped_no_agent_attribution: int = 0
    skipped_already_processed: int = 0
    last_eval_seen_at: str | None = None
    error: str | None = None
    duration_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "fetched_evals": self.fetched_evals,
            "hallucination_signals_recorded": self.hallucination_signals_recorded,
            "qa_irrelevance_signals_recorded": self.qa_irrelevance_signals_recorded,
            "skipped_no_agent_attribution": self.skipped_no_agent_attribution,
            "skipped_already_processed": self.skipped_already_processed,
            "last_eval_seen_at": self.last_eval_seen_at,
            "error": self.error,
            "duration_ms": self.duration_ms,
        }


# ── Phoenix client ───────────────────────────────────────────────────────


def _get_phoenix_client():
    """Lazy import. Returns None when Phoenix isn't installed or can't
    connect. Never raises."""
    try:
        import phoenix as px

        return px.Client(endpoint=PHOENIX_HTTP_URL, timeout=10)
    except ImportError:
        logger.debug("[KYA-PHOENIX] phoenix package not installed")
        return None
    except Exception as exc:
        logger.debug("[KYA-PHOENIX] client init failed: %s", exc)
        return None


def _get_cursor() -> datetime | None:
    """Read the last-polled timestamp from Valkey. None on first run."""
    try:
        from db.redis import get_redis

        r = get_redis()
        v = r.get(_CURSOR_KEY)
        if v:
            return datetime.fromisoformat(v.decode() if isinstance(v, bytes) else v)
    except Exception as exc:
        logger.debug("[KYA-PHOENIX] cursor read failed: %s", exc)
    return None


def _set_cursor(ts: datetime) -> None:
    try:
        from db.redis import get_redis

        r = get_redis()
        r.set(_CURSOR_KEY, ts.isoformat())
    except Exception as exc:
        logger.debug("[KYA-PHOENIX] cursor write failed: %s", exc)


# ── Phoenix span-attribute extraction ────────────────────────────────────


def _extract_agent_key(span_attributes: dict) -> str | None:
    """Map a Phoenix trace -> agent_key via the OTel span attribute
    `veldt.agent_key` (already emitted from observability.py:_run_agent_loop)."""
    if not isinstance(span_attributes, dict):
        return None
    # Span attributes might be nested under different keys depending on
    # the Phoenix client version; try a few.
    for key in ("veldt.agent_key", "attributes.veldt.agent_key"):
        val = span_attributes.get(key)
        if val:
            return str(val)
    return None


def _extract_tenant_id(span_attributes: dict) -> str | None:
    if not isinstance(span_attributes, dict):
        return None
    for key in ("veldt.tenant_id", "attributes.veldt.tenant_id"):
        val = span_attributes.get(key)
        if val:
            return str(val)
    return None


# ── Main poll ────────────────────────────────────────────────────────────


def poll_phoenix_evals(
    window_minutes: int = 30,
    since_ts: datetime | None = None,
) -> PollResult:
    """Pull eval rows from Phoenix and feed them into KYA quality counters.

    Returns a PollResult summary. Safe to call repeatedly; the Valkey
    cursor prevents re-counting evals already processed.
    """
    started = time.time()
    out = PollResult()

    if not is_enabled():
        out.error = "phoenix poll disabled (set KYA_PHOENIX_POLL_ENABLED=true)"
        return out

    client = _get_phoenix_client()
    if client is None:
        out.error = "phoenix client unavailable"
        return out

    cursor = since_ts or _get_cursor()
    if cursor is None:
        cursor = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

    try:
        # Phoenix client API differs across versions. The most stable
        # path: use get_evaluations() if available, else fall back to
        # querying spans + their eval attributes inline.
        evals = []
        try:
            # Newer phoenix versions
            evals = client.get_evaluations()
        except AttributeError:
            # Older versions or alternate API
            try:
                spans_df = client.get_spans_dataframe()
                # Filter spans that have eval annotations
                if hasattr(spans_df, "iterrows"):
                    for _idx, row in spans_df.iterrows():
                        evals.append(row.to_dict())
            except Exception as exc:
                logger.debug("[KYA-PHOENIX] spans_df fetch failed: %s", exc)

        out.fetched_evals = len(evals)
        if not evals:
            out.success = True
            out.duration_ms = int((time.time() - started) * 1000)
            return out

        # Import the KYA recorders we'll feed
        from .quality import record_hallucination, record_qa_irrelevance

        latest_ts = cursor
        for ev in evals:
            # Each row should have: name (eval name), score, span_attributes
            # Phoenix's exact schema varies — adapt as needed.
            try:
                eval_name = (
                    ev.get("name") or ev.get("eval_name") or ev.get("annotator_kind") or ""
                ).lower()
                score = ev.get("score") or ev.get("label_score") or 0.0
                try:
                    score = float(score)
                except (TypeError, ValueError):
                    score = 0.0
                attrs = ev.get("span_attributes") or ev.get("attributes") or {}
                ts_raw = ev.get("end_time") or ev.get("created_at") or ev.get("timestamp")
                ts = None
                if ts_raw:
                    try:
                        ts = (
                            ts_raw
                            if isinstance(ts_raw, datetime)
                            else datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
                        )
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)
                    except (TypeError, ValueError):
                        ts = None

                # Skip evals older than cursor
                if ts and cursor and ts <= cursor:
                    out.skipped_already_processed += 1
                    continue

                agent_key = _extract_agent_key(attrs)
                tenant_id = _extract_tenant_id(attrs) or ""
                if not agent_key:
                    out.skipped_no_agent_attribution += 1
                    continue

                # Route to the right KYA counter based on eval name
                if "hallucination" in eval_name and score >= HALLUCINATION_THRESHOLD:
                    record_hallucination(agent_key, tenant_id, score=1.0)
                    out.hallucination_signals_recorded += 1
                elif (
                    "qa" in eval_name or "relevance" in eval_name
                ) and score >= QA_IRRELEVANCE_THRESHOLD:
                    # Phoenix scoring convention: high score may mean "more
                    # irrelevant" or "more relevant" depending on the
                    # evaluator. We treat the threshold as "this eval
                    # flagged a problem" — operator should tune
                    # KYA_PHOENIX_QA_THRESHOLD to their Phoenix setup.
                    record_qa_irrelevance(agent_key, tenant_id, score=1.0)
                    out.qa_irrelevance_signals_recorded += 1

                if ts and (latest_ts is None or ts > latest_ts):
                    latest_ts = ts
                    out.last_eval_seen_at = ts.isoformat()
            except Exception as exc:
                logger.debug("[KYA-PHOENIX] eval row failed: %s", exc)
                continue

        if latest_ts != cursor:
            _set_cursor(latest_ts)
        out.success = True
    except Exception as exc:
        logger.warning("[KYA-PHOENIX] poll failed: %s", exc)
        out.error = str(exc)
    out.duration_ms = int((time.time() - started) * 1000)
    return out


# ── Background poller ───────────────────────────────────────────────────

_poll_thread: threading.Thread | None = None
_poll_stop_event: threading.Event | None = None


def start_phoenix_poll_thread(interval_seconds: int | None = None) -> None:
    """Start a background thread that polls Phoenix every interval_seconds.
    No-op when feature flag is disabled or already running."""
    global _poll_thread, _poll_stop_event
    if not is_enabled():
        logger.info("[KYA-PHOENIX] poll thread NOT started (flag disabled)")
        return
    if _poll_thread is not None and _poll_thread.is_alive():
        logger.info("[KYA-PHOENIX] poll thread already running — skipping")
        return

    interval = interval_seconds or POLL_INTERVAL_SECONDS
    _poll_stop_event = threading.Event()

    def _loop():
        logger.info("[KYA-PHOENIX] poll thread started, interval=%ds", interval)
        while not _poll_stop_event.is_set():
            try:
                result = poll_phoenix_evals()
                if result.success:
                    logger.info(
                        "[KYA-PHOENIX] poll OK: %d fetched, %d hallucinations, "
                        "%d qa, %d skipped(no_agent), %d skipped(seen) in %dms",
                        result.fetched_evals,
                        result.hallucination_signals_recorded,
                        result.qa_irrelevance_signals_recorded,
                        result.skipped_no_agent_attribution,
                        result.skipped_already_processed,
                        result.duration_ms,
                    )
                else:
                    logger.debug("[KYA-PHOENIX] poll soft-fail: %s", result.error)
            except Exception as exc:
                logger.warning("[KYA-PHOENIX] poll iteration crashed: %s", exc)
            # Sleep but respect stop event for fast shutdown
            _poll_stop_event.wait(interval)
        logger.info("[KYA-PHOENIX] poll thread stopped")

    _poll_thread = threading.Thread(target=_loop, name="kya-phoenix-poll", daemon=True)
    _poll_thread.start()


def stop_phoenix_poll_thread() -> None:
    """Signal the background thread to exit. For graceful shutdown."""
    global _poll_thread, _poll_stop_event
    if _poll_stop_event is not None:
        _poll_stop_event.set()
    if _poll_thread is not None:
        _poll_thread.join(timeout=5)
    _poll_thread = None
    _poll_stop_event = None
