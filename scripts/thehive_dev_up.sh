#!/usr/bin/env bash
# Start (or create) a local TheHive 5 for testing the --case output channel.
#
# Runs TheHive as a single container on its embedded database and index
# (BerkeleyDB + Lucene) — fine for dev, explicitly not for production,
# where TheHive wants Cassandra + Elasticsearch underneath. On a virgin
# instance this also bootstraps an organisation, an analyst user for the
# copilot, and an API key (printed once — put it in .env; it cannot be
# read back later, only regenerated).
#
# Usage:
#   ./scripts/thehive_dev_up.sh
set -euo pipefail

NAME="${THEHIVE_CONTAINER:-thehive-dev}"
IMAGE="strangebee/thehive:5.7.5"
URL="http://127.0.0.1:9000"

if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon not reachable from this shell."
  echo "If you were just added to the docker group, re-login or run:"
  echo "  sg docker -c $0"
  exit 1
fi

if [ -n "$(docker ps -q -f "name=^${NAME}\$")" ]; then
  echo "TheHive container already running."
elif [ -n "$(docker ps -aq -f "name=^${NAME}\$")" ]; then
  docker start "$NAME" >/dev/null
  echo "TheHive container restarted."
else
  docker run -d --name "$NAME" -p 127.0.0.1:9000:9000 \
    -v thehive-db:/opt/thp/thehive/db \
    -v thehive-index:/opt/thp/thehive/index \
    -v thehive-data:/opt/thp/thehive/data \
    "$IMAGE" >/dev/null
  echo "TheHive container created ($IMAGE)."
fi

up=""
for i in $(seq 1 60); do
  if curl -s "$URL/api/status" >/dev/null 2>&1; then
    echo "TheHive up (~$((i * 5))s): $URL"
    up=1
    break
  fi
  sleep 5
done
[ -n "$up" ] || { echo "TheHive failed to start; check: docker logs $NAME"; exit 1; }

# One-time bootstrap with the image's default admin credentials. Alerts
# cannot live in the built-in admin organisation, so the copilot needs a
# real org and an analyst-profile user of its own.
if curl -s -u admin@thehive.local:secret "$URL/api/v1/organisation/soc" \
    | grep -q '"name":"soc"'; then
  echo "Organisation 'soc' already bootstrapped."
  echo "Console: $URL (admin@thehive.local / secret)"
else
  curl -s -u admin@thehive.local:secret -H 'Content-Type: application/json' \
    -d '{"name":"soc","description":"soc-copilot dev organisation"}' \
    "$URL/api/v1/organisation" >/dev/null
  curl -s -u admin@thehive.local:secret -H 'Content-Type: application/json' \
    -d '{"login":"copilot@soc.local","name":"SOC Copilot","profile":"analyst","organisation":"soc"}' \
    "$URL/api/v1/user" >/dev/null
  KEY="$(curl -s -u admin@thehive.local:secret -X POST \
    "$URL/api/v1/user/copilot@soc.local/key/renew")"
  echo "Bootstrapped organisation 'soc' and user copilot@soc.local."
  echo "Add these to .env (the key is shown only once):"
  echo "  THEHIVE_URL=$URL"
  echo "  THEHIVE_API_KEY=$KEY"
  echo "  THEHIVE_ORGANISATION=soc"
fi
