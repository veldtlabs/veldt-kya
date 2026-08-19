#!/usr/bin/env bash
# Veldt KYA — Claude Code PreToolUse hook.
# Reads a Claude Code hook payload on stdin, asks the KYA gateway for a
# verdict, and translates the verdict back into a Claude Code hook response.
#
# Env:
#   KYA_GATEWAY_URL       default http://localhost:18080
#   KYA_HOOK_DID          REQUIRED  (subject DID passed as X-KYA-DID)
#   KYA_HOOK_TIMEOUT_SEC  default 5
#   KYA_HOOK_FAIL_OPEN    if set to 1, allow on gateway failure
#                         (availability tradeoff; default is fail-CLOSED).

# Preflight: emit a static deny JSON before any tool (jq / curl) is
# invoked. If either binary is missing we cannot reliably parse the
# gateway response or emit a well-formed Claude Code hook JSON — so
# fail-CLOSED with a human-readable reason. Runs BEFORE `set -euo
# pipefail` so a missing binary doesn't crash the shell.
if ! command -v jq >/dev/null 2>&1; then
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Veldt hook: jq missing on PATH; failing closed. Install jq."}}\n'
  exit 0
fi
if ! command -v curl >/dev/null 2>&1; then
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Veldt hook: curl missing on PATH; failing closed. Install curl."}}\n'
  exit 0
fi

set -euo pipefail

GATEWAY_URL="${KYA_GATEWAY_URL:-http://localhost:18080}"
TIMEOUT="${KYA_HOOK_TIMEOUT_SEC:-5}"
DID="${KYA_HOOK_DID:-}"

emit_deny() {
  local reason="$1"
  jq -cn --arg r "$reason" \
    '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'
  exit 0
}

emit_ask() {
  local reason="$1"
  jq -cn --arg r "$reason" \
    '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"ask",permissionDecisionReason:$r}}'
  exit 0
}

fail() {
  local reason="$1"
  if [[ "${KYA_HOOK_FAIL_OPEN:-0}" == "1" ]]; then
    echo "veldt-hook: $reason (fail-open: allowing)" >&2
    exit 0
  fi
  emit_deny "Veldt gateway unreachable; failing closed ($reason)"
}

if [[ -z "$DID" ]]; then
  emit_deny "Veldt: KYA_HOOK_DID env var not set; refusing to call gateway"
fi

INPUT="$(cat)"
if ! REQ="$(printf '%s' "$INPUT" | jq -c '{tool_name, tool_input}' 2>/dev/null)"; then
  fail "malformed hook stdin"
fi

HTTP_BODY_FILE="$(mktemp)"
trap 'rm -f "$HTTP_BODY_FILE"' EXIT

HTTP_CODE="$(curl -sS -o "$HTTP_BODY_FILE" -w '%{http_code}' \
  --max-time "$TIMEOUT" \
  -X POST "$GATEWAY_URL/v1/policy/decide" \
  -H 'Content-Type: application/json' \
  -H "X-KYA-DID: $DID" \
  --data "$REQ" 2>/dev/null)" || fail "curl error"

if [[ "$HTTP_CODE" != "200" ]]; then
  fail "gateway HTTP $HTTP_CODE"
fi

BODY="$(cat "$HTTP_BODY_FILE")"
VERDICT="$(printf '%s' "$BODY" | jq -r '.verdict // empty' 2>/dev/null || true)"
[[ -z "$VERDICT" ]] && fail "gateway response missing verdict"

case "$VERDICT" in
  allow)
    exit 0
    ;;
  deny|block)
    REASON="$(printf '%s' "$BODY" | jq -r '
      "Veldt: " + ((.reason_codes // []) | join(",") | if . == "" then "denied" else . end)
        + " [signal=" + (.signal_kind // "unknown") + "]"')"
    emit_deny "$REASON"
    ;;
  flag_for_review)
    REASON="$(printf '%s' "$BODY" | jq -r '
      "Veldt: pending human review (id=" + (.pending_id // "unknown") + ")"')"
    emit_ask "$REASON"
    ;;
  *)
    fail "unknown verdict '$VERDICT'"
    ;;
esac
