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
# The compose file mounts $AUDIT_TEST_LOG_DIR at /var/log/audit/testpod, which
# is the pod-name level the production glob (/var/log/audit/*/*.jsonl) expects.
# Without this the shipper starts fine and watches an empty directory, which
# looks exactly like "the package wrote nothing".
export AUDIT_TEST_LOG_DIR="$LOG_DIR"
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
# These MUST hard-fail. An earlier version printed the status code and carried
# on; the template PUT was returning 400 (a misspelled index setting) and the
# data stream was then auto-created with a DYNAMIC mapping. Everything
# downstream still looked green — documents indexed, the field count was
# comfortably under 200 — because a small demo does not generate enough
# distinct fields to notice. That is D-11's one-way door, and it is only
# fixable by a reindex.
put_or_die() { # url file label
  code=$(curl -sS -XPUT "$1" -H 'Content-Type: application/json' \
         --data-binary "@$2" -o /tmp/audit-put-$3.json -w '%{http_code}')
  if [ "$code" != "200" ]; then
    fail "$3 install returned HTTP $code"; head -c 500 /tmp/audit-put-$3.json; echo; exit 1
  fi
  echo "$3: $code"
}
# The ILM API accepts only the "policy" key and rejects the file's _meta
# envelope outright. demo/ilm_body.py strips it and resolves the retention
# knob into the delete phase, exactly as bootstrap.py does.
"$PY" demo/ilm_body.py > /tmp/audit-ilm-body.json || { fail "could not build the ILM body"; exit 1; }
# Canonical names, taken from infra/elasticsearch/bootstrap.py — NOT invented
# here. The template's settings.index.lifecycle.name points at
# "apiaudit-ilm", so a policy installed under any other name silently
# never attaches; and the template must be "logs-apiaudit" or it collides
# with the one the Tier 1 suite installs (same patterns, same priority,
# which Elasticsearch rejects outright).
put_or_die "http://127.0.0.1:9200/_ilm/policy/apiaudit-ilm" /tmp/audit-ilm-body.json ilm
put_or_die "http://127.0.0.1:9200/_index_template/logs-apiaudit" infra/elasticsearch/template-apiaudit.json template

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

step "Waiting for the sink to flush"
# The sink batches: it flushes on an interval or when the queue passes a size
# threshold, whichever comes first. Checking the file the instant the last
# response returns is a race against that interval, not a test of anything.
for i in $(seq 1 30); do
  lines=$(cat "$LOG_DIR"/*.jsonl 2>/dev/null | wc -l)
  [ "${lines:-0}" -ge 12 ] && { echo "$lines lines on disk after ${i}s"; break; }
  sleep 1
done

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
