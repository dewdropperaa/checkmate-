#!/usr/bin/env bash
# Post-deploy smoke test for OWASP ZAP + backend readiness.
#
# Verifies:
#   1. ZAP Compose service reaches healthy within a timeout
#   2. GET /health reports zap_ready=true (live API probe)
#   3. A minimal authorized scan completes with ZAP exercised
#      (not skipped as unreachable)
#
# Usage (from backend/):
#   export ZAP_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
#   export AUTHORIZED_TARGETS=example.com
#   docker compose up -d --build
#   bash scripts/smoke_zap_deploy.sh
#
# Optional env:
#   API_BASE, SMOKE_TARGET, ZAP_HEALTH_TIMEOUT_SECS, SCAN_TIMEOUT_SECS,
#   COMPOSE_FILE, API_KEY, FIREBASE_ID_TOKEN

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

API_BASE="${API_BASE:-http://127.0.0.1:8000}"
SMOKE_TARGET="${SMOKE_TARGET:-https://example.com}"
ZAP_HEALTH_TIMEOUT_SECS="${ZAP_HEALTH_TIMEOUT_SECS:-300}"
SCAN_TIMEOUT_SECS="${SCAN_TIMEOUT_SECS:-900}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"

log() { printf '[smoke-zap] %s\n' "$*"; }
fail() { printf '[smoke-zap] ERROR: %s\n' "$*" >&2; exit 1; }

urlencode() {
  python -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$1"
}

auth_curl() {
  local args=()
  if [[ -n "${API_KEY:-}" ]]; then
    args+=(-H "X-API-Key: ${API_KEY}")
  fi
  if [[ -n "${FIREBASE_ID_TOKEN:-}" ]]; then
    args+=(-H "Authorization: Bearer ${FIREBASE_ID_TOKEN}")
  fi
  curl -sf "$@" "${args[@]}"
}

log "Waiting for zap service healthy (timeout ${ZAP_HEALTH_TIMEOUT_SECS}s)..."
deadline=$((SECONDS + ZAP_HEALTH_TIMEOUT_SECS))
while true; do
  if docker compose -f "$COMPOSE_FILE" ps zap 2>/dev/null | grep -qi healthy; then
    log "ZAP container is healthy"
    break
  fi
  if (( SECONDS >= deadline )); then
    docker compose -f "$COMPOSE_FILE" ps zap || true
    docker compose -f "$COMPOSE_FILE" logs --tail=80 zap || true
    fail "ZAP did not become healthy within ${ZAP_HEALTH_TIMEOUT_SECS}s"
  fi
  sleep 5
done

log "Probing GET ${API_BASE}/health for zap_ready..."
deadline=$((SECONDS + 120))
while true; do
  body="$(curl -sf "${API_BASE}/health" || true)"
  if printf '%s' "$body" | python -c "import sys,json; d=json.load(sys.stdin); raise SystemExit(0 if (d.get('zap_ready') or (d.get('toolchain') or {}).get('zap_ready')) else 1)"; then
    log "Backend reports ZAP ready"
    break
  fi
  if (( SECONDS >= deadline )); then
    fail "GET /health did not report zap_ready within 120s. Last body: ${body:-<empty>}"
  fi
  sleep 3
done

TARGET_Q="$(urlencode "$SMOKE_TARGET")"
log "Starting minimal scan against ${SMOKE_TARGET}..."
scan_resp="$(auth_curl -X POST "${API_BASE}/scan" \
  -H "Content-Type: application/json" \
  -d "{\"target\": \"${SMOKE_TARGET}\", \"confirmed_authorized\": true}")" \
  || fail "POST /scan failed — is ${SMOKE_TARGET} on AUTHORIZED_TARGETS?"

scan_id="$(printf '%s' "$scan_resp" | python -c "import sys,json; print(json.load(sys.stdin)['scan_id'])")"
log "scan_id=${scan_id}"

approve_if_needed() {
  local status_body="$1"
  local action
  action="$(printf '%s' "$status_body" | python -c "
import sys, json
d = json.load(sys.stdin)
status = (d.get('status') or '').lower()
planned = d.get('planned_active_tests') or ['zap']
if status in ('awaiting_approval', 'waiting_for_approval', 'paused') or d.get('awaiting_approval'):
    print(json.dumps(planned if isinstance(planned, list) else ['zap']))
")"
  if [[ -n "$action" ]]; then
    log "Approving active tools: ${action}"
    auth_curl -X POST "${API_BASE}/scan/${scan_id}/approve?target=${TARGET_Q}" \
      -H "Content-Type: application/json" \
      -d "{\"approved\": true, \"approved_tools\": ${action}}" >/dev/null \
      || log "Approve call non-success (scan may already be running)"
  fi
}

log "Polling scan (timeout ${SCAN_TIMEOUT_SECS}s)..."
deadline=$((SECONDS + SCAN_TIMEOUT_SECS))
final_status=""
while true; do
  status_body="$(auth_curl "${API_BASE}/scan/${scan_id}/status?target=${TARGET_Q}")" \
    || fail "Could not poll scan status"
  approve_if_needed "$status_body"

  final_status="$(printf '%s' "$status_body" | python -c "import sys,json; print(json.load(sys.stdin).get('status') or '')")"
  case "${final_status}" in
    scored|completed|complete|report_ready|failed|error|rejected)
      break
      ;;
  esac
  if (( SECONDS >= deadline )); then
    fail "Scan did not finish within ${SCAN_TIMEOUT_SECS}s (status=${final_status})"
  fi
  sleep 5
done

log "Final status=${final_status}"
[[ "${final_status}" != "failed" && "${final_status}" != "error" && "${final_status}" != "rejected" ]] \
  || fail "Scan ended in terminal failure state: ${final_status}"

report_body="$(auth_curl "${API_BASE}/scan/${scan_id}/report?target=${TARGET_Q}")" \
  || fail "Could not fetch scan report"

printf '%s' "$report_body" | python -c "
import json, sys
d = json.load(sys.stdin)
cov = (d.get('severity_scores') or {}).get('scan_coverage') or {}
meta = d.get('detection_metadata') or {}
errors = meta.get('errors') or {}
notes = list(cov.get('coverage_notes') or meta.get('coverage_notes') or [])
failed = set(cov.get('modules_failed') or [])
zap_err = str(errors.get('active_zap') or errors.get('zap') or '')
joined_notes = ' '.join(str(n) for n in notes)
print('modules_failed=', sorted(failed))
print('coverage_notes=', notes)
print('zap_error=', zap_err or None)
if 'ZAP unavailable' in joined_notes:
    raise SystemExit('ZAP was skipped as unavailable')
if any(x in zap_err.lower() for x in ('unreachable', 'unavailable', 'connection refused')):
    raise SystemExit(f'ZAP connectivity failure: {zap_err}')
# Success if zap ran, or failed only for non-connectivity reasons (e.g. target timeout).
print('smoke ok: ZAP path reached without connectivity loss')
"

log "PASS: ZAP healthy, /health zap_ready, scan completed through active detection"
