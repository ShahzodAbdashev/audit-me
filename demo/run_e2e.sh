#!/usr/bin/env bash
# End-to-end: FastAPI -> JSONL -> Filebeat -> Elasticsearch -> assertions.
#
# This is the Tier 1 gate. Everything before it (597 unit + Tier 2 tests) proves
# the package writes correct JSONL. This proves the rest of the pipeline —
# Filebeat's ndjson decode, data_stream routing, and Elasticsearch actually
# enforcing dynamic:false — which nothing else can.
#
#   ./demo/run_e2e.sh            full run
#   ./demo/run_e2e.sh --keep     leave the stack up afterwards
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"; PY="$ROOT/.venv/bin/python"
COMPOSE="tests/integration/docker-compose.test.yml"
LOG_DIR="${AUDIT_LOG_DIR:-/tmp/audit-demo/$(hostname)}"
KEEP=0; [ "${1:-}" = "--keep" ] && KEEP=1
APP_PID=""

step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAILED: %s\033[0m\n' "$1"; }

cleanup() {
  [ -n "$APP_PID" ] && kill "$APP_PID" 2>/dev/null && wait "$APP_PID" 2>/dev/null
  if [ "$KEEP" = "0" ]; then
    step "Tearing down"; docker compose -f "$COMPOSE" down -v >/dev/null 2>&1
  else
    echo; echo "Stack left running. ES: http://127.0.0.1:9200  ·  down: docker compose -f $COMPOSE down -v"
  fi
}
trap cleanup EXIT

step "Preflight"
if ! docker ps >/dev/null 2>&1; then
  fail "cannot reach the Docker daemon"
  cat <<'MSG'

  You are not in the "docker" group, so this script cannot start Elasticsearch.
  Fix it once:

      sudo usermod -aG docker $USER

  then log out and back in (a group change needs a new login), or start a new
  session, and run this script again. Verify with:  docker ps

MSG
  exit 2
fi
echo "docker ok: $(docker --version)"
rm -rf "$LOG_DIR"; mkdir -p "$LOG_DIR"; chmod 777 "$LOG_DIR"
echo "log dir: $LOG_DIR"

step "Starting Elasticsearch + Filebeat"
docker compose -f "$COMPOSE" up -d --wait 2>&1 | tail -5 || {
  docker compose -f "$COMPOSE" up -d 2>&1 | tail -20; }

step "Waiting for Elasticsearch"
for i in $(seq 1 90); do
  status=$(curl -s "http://127.0.0.1:9200/_cluster/health" 2>/dev/null \
           | grep -o '"status":"[a-z]*"' | cut -d'"' -f4)
  [ "$status" = "green" ] || [ "$status" = "yellow" ] && { echo "cluster is $status after ${i}s"; break; }
  sleep 1
done
[ -z "${status:-}" ] && { fail "Elasticsearch never became healthy"; docker compose -f "$COMPOSE" logs elasticsearch | tail -30; exit 1; }

step "Installing the index template and ILM policy (D-11: BEFORE any write)"
# A data stream created before its template gets a dynamic mapping and cannot
# be fixed without a reindex — plan §10 is emphatic about the ordering.
curl -sS -XPUT "http://127.0.0.1:9200/_ilm/policy/apiaudit" \
  -H 'Content-Type: application/json' \
  --data-binary "@infra/elasticsearch/ilm-apiaudit.json" -o /dev/null -w 'ilm: %{http_code}\n'
curl -sS -XPUT "http://127.0.0.1:9200/_index_template/apiaudit" \
  -H 'Content-Type: application/json' \
  --data-binary "@infra/elasticsearch/template-apiaudit.json" -o /dev/null -w 'template: %{http_code}\n'

step "Starting the FastAPI service (real uvicorn, real socket)"
AUDIT_LOG_DIR="$LOG_DIR" AUDIT_ENVIRONMENT=demo \
  "$PY" -m uvicorn demo.app:app --host 127.0.0.1 --port 8080 --log-level warning &
APP_PID=$!
for i in $(seq 1 30); do
  curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1 && { echo "service up after ${i}s (pid $APP_PID)"; break; }
  sleep 1
done

step "Sending traffic"
"$PY" demo/traffic.py send || { fail "traffic generator errored"; exit 1; }

step "Verifying the JSONL on disk (before Elasticsearch is involved)"
# If this fails, the problem is the package. If it passes and the ES check
# below fails, the problem is Filebeat or the cluster. Splitting them is worth
# the ten seconds.
"$PY" demo/traffic.py verify --from-file "$LOG_DIR" --expect 12 || {
  fail "the package wrote bad JSONL — stopping before blaming Elasticsearch"; exit 1; }

step "Waiting for the file to reach Elasticsearch"
echo "JSONL on disk:"; wc -l "$LOG_DIR"/*.jsonl 2>/dev/null || echo "  (no file yet)"
for i in $(seq 1 60); do
  curl -s -XPOST "http://127.0.0.1:9200/_refresh" >/dev/null 2>&1
  n=$(curl -s "http://127.0.0.1:9200/logs-apiaudit.orders_api-demo/_count" 2>/dev/null \
      | grep -o '"count":[0-9]*' | cut -d: -f2)
  [ "${n:-0}" -ge 12 ] 2>/dev/null && { echo "$n documents indexed after ${i}s"; break; }
  sleep 1
done
[ "${n:-0}" = "0" ] && { fail "nothing reached Elasticsearch"; docker compose -f "$COMPOSE" logs filebeat | tail -40; }

step "Verifying against Elasticsearch"
"$PY" demo/traffic.py verify --expect 12; VERIFY=$?

step "Tier 1 acceptance suite (AC-01..AC-26 against real Elasticsearch)"
"$PY" -m pytest tests/integration -m integration -q 2>&1 | tail -25; TIER1=${PIPESTATUS[0]}

step "Result"
echo "demo verification : $([ $VERIFY -eq 0 ] && echo PASS || echo FAIL)"
echo "tier 1 suite      : $([ $TIER1 -eq 0 ] && echo PASS || echo FAIL)"
[ $VERIFY -eq 0 ] && [ $TIER1 -eq 0 ] && { echo; echo "END-TO-END VERIFIED"; exit 0; }
echo; fail "see above"; exit 1
