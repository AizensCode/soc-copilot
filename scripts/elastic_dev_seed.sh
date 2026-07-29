#!/usr/bin/env bash
# Seed a local dev Elasticsearch with demo detection alerts for soc-copilot.
#
# Creates the alerts index (explicit mapping for the fields the copilot's
# fetch query filters and sorts on) and bulk-indexes three ECS-shaped
# detection alerts, one per enrichment route:
#   - SSH brute force from a Tor exit node   -> ips    -> AbuseIPDB
#   - DNS tunneling beacon to a fresh domain -> domains -> URLScan
#   - EICAR test file on an endpoint         -> hashes -> VirusTotal
#
# Usage:
#   ES_PASS=<elastic password> ./scripts/elastic_dev_seed.sh
#   ES_URL / ES_USER / ALERTS_INDEX override the defaults below.
set -euo pipefail

ES_URL="${ES_URL:-http://127.0.0.1:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:?set ES_PASS to the elastic superuser password}"
ALERTS_INDEX="${ALERTS_INDEX:-soc-alerts-demo}"

auth=(-u "$ES_USER:$ES_PASS")
now() { date -u -d "$1 minutes ago" +"%Y-%m-%dT%H:%M:%SZ"; }

echo "Creating index $ALERTS_INDEX (idempotent)..."
curl -sS "${auth[@]}" -X PUT "$ES_URL/$ALERTS_INDEX" \
  -H 'Content-Type: application/json' -d '{
  "mappings": {
    "properties": {
      "@timestamp": {"type": "date"},
      "kibana": {"properties": {"alert": {"properties": {
        "uuid": {"type": "keyword"},
        "severity": {"type": "keyword"},
        "risk_score": {"type": "integer"},
        "workflow_status": {"type": "keyword"},
        "reason": {"type": "text"},
        "rule": {"properties": {
          "name": {"type": "keyword"},
          "description": {"type": "text"}
        }}
      }}}}
    }
  }
}' | grep -q '"acknowledged":true\|resource_already_exists' \
  && echo " index ok" || echo " (index may already exist)"

echo "Bulk-indexing 3 demo alerts..."
curl -sS "${auth[@]}" -X POST "$ES_URL/_bulk?refresh=true" \
  -H 'Content-Type: application/x-ndjson' --data-binary @- <<EOF | python3 -c "import json,sys; d=json.load(sys.stdin); print(' errors:', d['errors'])"
{"index": {"_index": "$ALERTS_INDEX", "_id": "es-demo-0001"}}
{"@timestamp": "$(now 15)", "kibana": {"alert": {"uuid": "es-demo-0001", "severity": "high", "risk_score": 73, "workflow_status": "open", "reason": "847 failed SSH logins from 185.220.101.47 to prod-web-02 within 3 minutes", "rule": {"name": "SSH brute force burst from single source", "description": "Flags more than 100 failed sshd logins from one source IP within 5 minutes"}}}, "event": {"category": ["authentication"], "type": ["start"], "outcome": "failure", "module": "system", "dataset": "system.auth"}, "host": {"name": "prod-web-02", "os": {"family": "debian"}}, "user": {"name": "root"}, "source": {"ip": "185.220.101.47", "geo": {"country_iso_code": "DE"}}, "message": "sshd: 847 failed password attempts for root/admin/ubuntu/oracle from 185.220.101.47 in 180s"}
{"index": {"_index": "$ALERTS_INDEX", "_id": "es-demo-0002"}}
{"@timestamp": "$(now 10)", "kibana": {"alert": {"uuid": "es-demo-0002", "severity": "high", "risk_score": 70, "workflow_status": "open", "reason": "High-entropy TXT query flood to upd-metrics-relay.xyz from WKSTN-114", "rule": {"name": "Possible DNS tunneling (TXT query flood)", "description": "Flags sustained high-rate TXT queries with high-entropy subdomains to a single registered domain"}}}, "event": {"category": ["network"], "dataset": "network_traffic.dns"}, "host": {"name": "WKSTN-114"}, "user": {"name": "l.tanaka"}, "source": {"ip": "10.20.14.114"}, "dns": {"type": "query", "question": {"name": "upd-metrics-relay.xyz", "type": "TXT"}}, "message": "412 TXT queries to upd-metrics-relay.xyz in 600s; avg subdomain entropy 3.9; no matching software inventory entry"}
{"index": {"_index": "$ALERTS_INDEX", "_id": "es-demo-0003"}}
{"@timestamp": "$(now 5)", "kibana": {"alert": {"uuid": "es-demo-0003", "severity": "critical", "risk_score": 90, "workflow_status": "open", "reason": "Malware signature matched for file invoice_scan.pdf.exe on FIN-LT-031", "rule": {"name": "Endpoint malware detection", "description": "AV engine signature match on file write"}}}, "event": {"category": ["malware"], "kind": "alert"}, "host": {"name": "FIN-LT-031"}, "user": {"name": "p.dubois"}, "file": {"name": "invoice_scan.pdf.exe", "path": "C:\\\\Users\\\\p.dubois\\\\Downloads\\\\invoice_scan.pdf.exe", "hash": {"sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe1a2c4538aabf651fd0f"}}, "process": {"name": "chrome.exe"}, "message": "AV engine quarantined invoice_scan.pdf.exe (signature: EICAR-Test-File) after download via chrome.exe"}
EOF

echo "Done. Verify with:"
echo "  curl -s -u \"\$ES_USER:\$ES_PASS\" '$ES_URL/$ALERTS_INDEX/_count'"
