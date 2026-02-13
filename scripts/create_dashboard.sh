#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ndjson="${script_dir}/../dashboards/ot-soc-dashboard.ndjson"

dashboards_url="${DASHBOARDS_URL:-http://localhost:15601}"
dashboards_user="${DASHBOARDS_USER:-admin}"
dashboards_pass="${DASHBOARDS_PASS:-SecureAdmin123!}"

if [ ! -f "${ndjson}" ]; then
  echo "ERROR: Dashboard export not found at ${ndjson}"
  exit 1
fi

response="$(curl -s -k -u "${dashboards_user}:${dashboards_pass}" \
  -H 'kbn-xsrf: true' \
  -H 'osd-xsrf: true' \
  -F "file=@${ndjson}" \
  "${dashboards_url}/api/saved_objects/_import?overwrite=true")"

echo "${response}"
if echo "${response}" | grep -q '"success":true'; then
  echo "Dashboard imported successfully."
else
  echo "Dashboard import may have failed. Check the response above."
  exit 1
fi
