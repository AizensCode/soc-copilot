#!/usr/bin/env bash
# Import the SOC Copilot analyst dashboard into a local dev Kibana.
#
# Installs (idempotently, overwrite on re-run):
#   - data views for soc-alerts-demo and soc-copilot-investigations
#   - saved searches: open detection alerts, latest investigations
#   - lens panels: verdict donut, alert-severity donut, top MITRE
#     techniques, investigations timeline
#   - the "SOC Copilot - Analyst Console" dashboard (30s auto-refresh)
#
# Usage:
#   ES_PASS=<elastic password> ./scripts/kibana_dashboard_import.sh
#   KIBANA_URL / ES_USER override the defaults below.
set -euo pipefail

KIBANA_URL="${KIBANA_URL:-http://127.0.0.1:5601}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:?set ES_PASS to the elastic superuser password}"
NDJSON="$(dirname "$0")/kibana_soc_dashboard.ndjson"

curl -sS -u "$ES_USER:$ES_PASS" -H "kbn-xsrf: true" \
  -X POST "$KIBANA_URL/api/saved_objects/_import?overwrite=true" \
  --form "file=@$NDJSON" | python3 -c "
import json, sys
r = json.load(sys.stdin)
print('imported:', r.get('successCount'), 'objects, success =', r.get('success'))
for e in r.get('errors', []):
    print('ERROR:', e.get('type'), e.get('id'), '-', e.get('error', {}).get('type'))
sys.exit(0 if r.get('success') else 1)
"

echo "Dashboard: $KIBANA_URL/app/dashboards#/view/soc-dashboard-console"
