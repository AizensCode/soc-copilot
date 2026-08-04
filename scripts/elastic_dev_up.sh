#!/usr/bin/env bash
# Start (or restart) the local dev Elastic stack after a reboot.
#
# The tarball-installed Elasticsearch and Kibana run as plain user
# processes (see README "Local Elastic dev stack"), so a WSL/host restart
# kills them. This brings both back and waits for health.
#
# Usage:
#   ./scripts/elastic_dev_up.sh              # uses ~/elastic-stack
#   STACK_DIR=/path ./scripts/elastic_dev_up.sh
set -euo pipefail

STACK_DIR="${STACK_DIR:-$HOME/elastic-stack}"
ES_DIR="$(echo "$STACK_DIR"/elasticsearch-*/)"
KB_DIR="$(echo "$STACK_DIR"/kibana-*/)"
ES_PASS="$(cat "$STACK_DIR/.es_pass")"

if curl -s -u "elastic:$ES_PASS" "http://127.0.0.1:9200/_cluster/health" >/dev/null 2>&1; then
  echo "Elasticsearch already up."
else
  (cd "$ES_DIR" && ES_JAVA_OPTS="${ES_JAVA_OPTS:--Xms1g -Xmx1g}" \
    nohup ./bin/elasticsearch > "$STACK_DIR/es.log" 2>&1 &)
  echo "Elasticsearch starting..."
fi

if curl -s "http://127.0.0.1:5601/api/status" >/dev/null 2>&1; then
  echo "Kibana already up."
else
  (cd "$KB_DIR" && nohup ./bin/kibana > "$STACK_DIR/kibana.log" 2>&1 &)
  echo "Kibana starting..."
fi

for i in $(seq 1 40); do
  status=$(curl -s -u "elastic:$ES_PASS" "http://127.0.0.1:9200/_cluster/health" \
    | grep -o '"status":"[a-z]*"' || true)
  if [ -n "$status" ]; then echo "Elasticsearch up (~$((i*3))s): $status"; break; fi
  sleep 3
done
[ -n "${status:-}" ] || { echo "Elasticsearch failed to start; see $STACK_DIR/es.log"; exit 1; }

for i in $(seq 1 60); do
  if curl -s "http://127.0.0.1:5601/api/status" | grep -q '"level":"available"'; then
    echo "Kibana available (~$((i*5))s): http://127.0.0.1:5601"; exit 0
  fi
  sleep 5
done
echo "Kibana not available yet; see $STACK_DIR/kibana.log (ES itself is up)"
