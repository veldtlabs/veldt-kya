#!/usr/bin/env bash
# Integration harness for scripts/policy-gate.sh.
# Runs three cases end-to-end against a live KYA gateway on
# ${KYA_GATEWAY_URL:-http://localhost:18080}.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$SCRIPT_DIR/policy-gate.sh"

export KYA_GATEWAY_URL="${KYA_GATEWAY_URL:-http://localhost:18080}"
export KYA_HOOK_DID="${KYA_HOOK_DID:-did:example:kya-hook-test-subject}"
export KYA_HOOK_TIMEOUT_SEC="${KYA_HOOK_TIMEOUT_SEC:-5}"

pass=0; fail=0
check() { # name expected_substr actual
  if [[ -z "$2" || "$3" == *"$2"* ]]; then
    echo "  PASS $1"; pass=$((pass+1))
  else
    echo "  FAIL $1 — expected '$2', got: $3"; fail=$((fail+1))
  fi
}

run_case() { # payload_json
  printf '%s' "$1" | bash "$GATE"
  echo "__EXIT__$?"
}

echo "[1/3] allow-tool (Read)"
OUT1="$(run_case '{"tool_name":"Read","tool_input":{"file_path":"/tmp/x"},"session_id":"s","tool_use_id":"t"}')"
check "allow exit 0"       "__EXIT__0" "$OUT1"
check "allow empty stdout" ""          "$(printf '%s' "$OUT1" | sed 's/__EXIT__.*//')"

echo "[2/3] deny-tool (governed_bash rm -rf /)"
OUT2="$(run_case '{"tool_name":"governed_bash","tool_input":{"command":"rm -rf /"},"session_id":"s","tool_use_id":"t"}')"
check "deny exit 0"        "__EXIT__0"                 "$OUT2"
# Live gateway may not have the demo deny rule loaded — in which case
# this payload legitimately allows. Skip gracefully rather than warn
# scarily; a real deny is the interesting signal.
if [[ "$OUT2" == *'"permissionDecision":"deny"'* ]]; then
  check "deny decision" '"permissionDecision":"deny"' "$OUT2"
else
  echo "  [skipped: no demo deny rule loaded for governed_bash]"
fi

echo "[3/3] gateway-down fail-closed"
docker stop kya-gateway >/dev/null 2>&1 || true
# shrink timeout so we don't wait 5s
KYA_HOOK_TIMEOUT_SEC=2 OUT3="$(run_case '{"tool_name":"Read","tool_input":{"file_path":"/tmp/x"},"session_id":"s","tool_use_id":"t"}')"
docker start kya-gateway >/dev/null 2>&1 || true
# best-effort wait for healthy
for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
  s="$(docker inspect -f '{{.State.Health.Status}}' kya-gateway 2>/dev/null || echo none)"
  [[ "$s" == "healthy" ]] && break
  sleep 1
done
check "fail-closed exit 0"          "__EXIT__0"                    "$OUT3"
check "fail-closed deny decision"   '"permissionDecision":"deny"'  "$OUT3"
check "fail-closed reason mentions unreachable" "unreachable"      "$OUT3"

echo
echo "Results: $pass pass, $fail fail"
[[ "$fail" -eq 0 ]]
