#!/usr/bin/env bash
# Round-2 live gate: real Elasticsearch 8.13.4 + uvicorn app -> tests/integration/test_semantic_live_es.py
# Always removes the container on exit.
set -euo pipefail
cd "$(dirname "$0")/.."
NAME=gate2-es PORT=59800 PASS=gatePass1
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p "127.0.0.1:$PORT:9200" --memory 1500m \
  -e discovery.type=single-node -e ELASTIC_PASSWORD="$PASS" -e ES_JAVA_OPTS="-Xms512m -Xmx512m" \
  docker.elastic.co/elasticsearch/elasticsearch:8.13.4 >/dev/null
for _ in $(seq 120); do
  curl -sk -u "elastic:$PASS" "https://127.0.0.1:$PORT/_cluster/health?wait_for_status=yellow&timeout=1s" \
    | grep -q '"status"' && break
  sleep 1
done
GATE_ES_URL="https://127.0.0.1:$PORT" GATE_ES_PASSWORD="$PASS" \
  ./.venv/bin/python -m pytest tests/integration/test_semantic_live_es.py -m integration -p no:cacheprovider -o addopts="--strict-markers" -v "$@"
