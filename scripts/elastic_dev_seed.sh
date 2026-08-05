#!/usr/bin/env bash
# Seed a local dev Elasticsearch with demo detection alerts for soc-copilot.
#
# Creates the alerts index (explicit mapping for the fields the copilot's
# fetch query filters and sorts on) and bulk-indexes six ECS-shaped
# detection alerts:
#   - SSH brute force from a Tor exit node   -> ips    -> AbuseIPDB
#   - DNS tunneling beacon to a fresh domain -> domains -> URLScan
#   - EICAR test file on an endpoint         -> hashes -> VirusTotal
#   - Impossible-travel sign-in (account compromise -> TheHive case)
#   - Benign scanner auth burst (asset inventory -> auto-close candidate)
#   - Benign SCCM encoded PowerShell (asset inventory corroboration)
# The benign docs EVIDENCE benignity (recurrence labels, schedule windows,
# reverse DNS) and never assert it — "authorized X" prose in alert content
# is untrusted by design; the copilot verifies against the committed asset
# inventory (data/asset_context.json) instead.
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

echo "Bulk-indexing 6 demo alerts..."
curl -sS "${auth[@]}" -X POST "$ES_URL/_bulk?refresh=true" \
  -H 'Content-Type: application/x-ndjson' --data-binary @- <<EOF | python3 -c "import json,sys; d=json.load(sys.stdin); print(' errors:', d['errors'])"
{"index": {"_index": "$ALERTS_INDEX", "_id": "es-demo-0001"}}
{"@timestamp": "$(now 15)", "kibana": {"alert": {"uuid": "es-demo-0001", "severity": "high", "risk_score": 73, "workflow_status": "open", "reason": "847 failed SSH logins from 185.220.101.47 to prod-web-02 within 3 minutes", "rule": {"name": "SSH brute force burst from single source", "description": "Flags more than 100 failed sshd logins from one source IP within 5 minutes"}}}, "event": {"category": ["authentication"], "type": ["start"], "outcome": "failure", "module": "system", "dataset": "system.auth"}, "host": {"name": "prod-web-02", "os": {"family": "debian"}}, "user": {"name": "root"}, "source": {"ip": "185.220.101.47", "geo": {"country_iso_code": "DE"}}, "message": "sshd: 847 failed password attempts for root/admin/ubuntu/oracle from 185.220.101.47 in 180s"}
{"index": {"_index": "$ALERTS_INDEX", "_id": "es-demo-0002"}}
{"@timestamp": "$(now 10)", "kibana": {"alert": {"uuid": "es-demo-0002", "severity": "high", "risk_score": 70, "workflow_status": "open", "reason": "High-entropy TXT query flood to upd-metrics-relay.xyz from WKSTN-114", "rule": {"name": "Possible DNS tunneling (TXT query flood)", "description": "Flags sustained high-rate TXT queries with high-entropy subdomains to a single registered domain"}}}, "event": {"category": ["network"], "dataset": "network_traffic.dns"}, "host": {"name": "WKSTN-114"}, "user": {"name": "l.tanaka"}, "source": {"ip": "10.20.14.114"}, "dns": {"type": "query", "question": {"name": "upd-metrics-relay.xyz", "type": "TXT"}}, "message": "412 TXT queries to upd-metrics-relay.xyz in 600s; avg subdomain entropy 3.9; no matching software inventory entry"}
{"index": {"_index": "$ALERTS_INDEX", "_id": "es-demo-0003"}}
{"@timestamp": "$(now 5)", "kibana": {"alert": {"uuid": "es-demo-0003", "severity": "critical", "risk_score": 90, "workflow_status": "open", "reason": "Malware signature matched for file invoice_scan.pdf.exe on FIN-LT-031", "rule": {"name": "Endpoint malware detection", "description": "AV engine signature match on file write"}}}, "event": {"category": ["malware"], "kind": "alert"}, "host": {"name": "FIN-LT-031"}, "user": {"name": "p.dubois"}, "file": {"name": "invoice_scan.pdf.exe", "path": "C:\\\\Users\\\\p.dubois\\\\Downloads\\\\invoice_scan.pdf.exe", "hash": {"sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe1a2c4538aabf651fd0f"}}, "process": {"name": "chrome.exe"}, "message": "AV engine quarantined invoice_scan.pdf.exe (signature: EICAR-Test-File) after download via chrome.exe"}
{"index": {"_index": "$ALERTS_INDEX", "_id": "es-demo-0004"}}
{"@timestamp": "$(now 4)", "kibana": {"alert": {"uuid": "es-demo-0004", "severity": "high", "risk_score": 78, "workflow_status": "open", "reason": "Successful sign-in for c.moreau from 146.70.113.24 (AE) 22 minutes after a Lyon sign-in; second session reused an existing token", "rule": {"name": "Impossible travel: geographically distant sign-ins", "description": "Flags account sign-ins whose locations imply impossible travel velocity"}}}, "event": {"category": ["authentication"], "outcome": "success"}, "user": {"name": "c.moreau"}, "source": {"ip": "146.70.113.24", "geo": {"country_iso_code": "AE"}}, "message": "azure-ad-signin: success for c.moreau from 146.70.113.24 via Exchange ActiveSync, mfa satisfied_by_existing_token; prior sign-in from Lyon 22m earlier"}
{"index": {"_index": "$ALERTS_INDEX", "_id": "es-demo-0005"}}
{"@timestamp": "$(now 3)", "kibana": {"alert": {"uuid": "es-demo-0005", "severity": "medium", "risk_score": 47, "workflow_status": "open", "reason": "212 failed SSH logins for svc-qualys from 10.20.8.15 to app-db-14 within 5 minutes", "rule": {"name": "SSH brute force burst from single source", "description": "Flags more than 100 failed sshd logins from one source IP within 5 minutes"}}}, "event": {"category": ["authentication"], "outcome": "failure", "dataset": "system.auth"}, "host": {"name": "app-db-14.internal"}, "user": {"name": "svc-qualys"}, "source": {"ip": "10.20.8.15", "domain": "qualys-scanner-02.corp.internal"}, "message": "sshd: 212 failed password attempts for svc-qualys from 10.20.8.15 in 300s; no successful logins from this source in the window", "labels": {"prior_identical_bursts_30d": "4", "burst_window_utc": "03:00-04:00", "source_reverse_dns": "qualys-scanner-02.corp.internal"}}
{"index": {"_index": "$ALERTS_INDEX", "_id": "es-demo-0006"}}
{"@timestamp": "$(now 2)", "kibana": {"alert": {"uuid": "es-demo-0006", "severity": "medium", "risk_score": 52, "workflow_status": "open", "reason": "Encoded PowerShell spawned by CcmExec.exe on sccm-mp-01", "rule": {"name": "Endpoint encoded PowerShell detection", "description": "Flags powershell.exe launched with an encoded command"}}}, "event": {"category": ["process"], "type": ["start"]}, "host": {"name": "sccm-mp-01.corp.internal"}, "user": {"name": "SYSTEM"}, "process": {"name": "powershell.exe", "command_line": "powershell.exe -NonInteractive -ExecutionPolicy Bypass -EncodedCommand RwBlAHQALQBXAG0AaQBPAGIAagBlAGMAdAAgAFcAaQBuADMAMgBfAFAAcgBvAGQAdQBjAHQA", "code_signature": {"trusted": true, "subject_name": "Microsoft Windows", "status": "trusted"}, "parent": {"name": "CcmExec.exe", "executable": "C:\\\\Windows\\\\CCM\\\\CcmExec.exe", "code_signature": {"trusted": true, "subject_name": "Microsoft Corporation"}}}, "message": "EDR: encoded PowerShell spawned by CcmExec.exe as SYSTEM (decoded preview: Get-WmiObject Win32_Product)", "labels": {"prior_identical_executions_30d": "28", "recurrence_utc": "daily 04:00"}}
EOF

echo "Done. Verify with:"
echo "  curl -s -u \"\$ES_USER:\$ES_PASS\" '$ES_URL/$ALERTS_INDEX/_count'"
