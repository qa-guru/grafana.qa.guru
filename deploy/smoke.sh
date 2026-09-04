#!/usr/bin/env bash
# Smoke grafana.qa.guru: HTTPS health + admin basic-auth. Password never printed.
set -euo pipefail

ENV_FILE="${GRAFANA_ADMIN_ENV:-${HOME}/.config/grafana/admin.env}"
URL="${GRAFANA_URL:-https://grafana.qa.guru}"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "FAIL: ${ENV_FILE} missing" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

: "${GRAFANA_ADMIN_USER:?}"
: "${GRAFANA_ADMIN_PASSWORD:?}"

health="$(curl -sfS --max-time 20 "${URL}/api/health")"
echo "${health}" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("database")=="ok", d; print("health: ok", d.get("version",""))'

me="$(curl -sfS --max-time 20 -u "${GRAFANA_ADMIN_USER}:${GRAFANA_ADMIN_PASSWORD}" "${URL}/api/user")"
echo "${me}" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("user:", d.get("login"), d.get("email"), "admin="+str(d.get("isGrafanaAdmin")))'

ds="$(curl -sfS --max-time 20 -u "${GRAFANA_ADMIN_USER}:${GRAFANA_ADMIN_PASSWORD}" "${URL}/api/datasources")"
echo "${ds}" | python3 -c 'import json,sys; rows=json.load(sys.stdin); names=[r.get("name") for r in rows]; print("datasources:", ", ".join(names) or "(none)")'

echo "OK: ${URL}"
