#!/usr/bin/env bash
# rsync compose + provisioning to Box2 /opt/grafana.qa.guru and docker compose up.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HOST="${GRAFANA_DEPLOY_HOST:-box2-ci}"
REMOTE="/opt/grafana.qa.guru"
ENV_FILE="${GRAFANA_ADMIN_ENV:-${HOME}/.config/grafana/admin.env}"
OIDC_ENV_FILE="${GRAFANA_OIDC_ENV:-${HOME}/.config/grafana/oidc.env}"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "FAIL: ${ENV_FILE} missing (GRAFANA_ADMIN_USER / GRAFANA_ADMIN_PASSWORD)" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
# SSO secret (deploy/oidc.py seed-secret). This file rewrites .env from scratch, so the secret
# has to be re-emitted here — otherwise a plain re-install silently turns SSO off.
if [[ -f "${OIDC_ENV_FILE}" ]]; then
  # shellcheck disable=SC1090
  source "${OIDC_ENV_FILE}"
fi
set +a

if grep -qE '^\s*enabled\s*=\s*true' <(sed -n '/^\[auth.generic_oauth\]/,/^\[/p' "${ROOT}/grafana.ini") \
   && [[ -z "${GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET:-}" ]]; then
  echo "FAIL: grafana.ini enables generic_oauth but ${OIDC_ENV_FILE} has no secret" >&2
  echo "      run: python3 deploy/oidc.py seed-secret" >&2
  exit 1
fi

: "${GRAFANA_ADMIN_USER:?}"
: "${GRAFANA_ADMIN_PASSWORD:?}"
GRAFANA_ADMIN_EMAIL="${GRAFANA_ADMIN_EMAIL:-admin@qa.guru}"
GRAFANA_URL="${GRAFANA_URL:-https://grafana.qa.guru}"

ssh "${HOST}" "sudo mkdir -p '${REMOTE}' && sudo chown qaguru:qaguru '${REMOTE}'"

rsync -az --delete \
  --exclude '.git/' \
  --exclude '.env' \
  --exclude 'deploy/' \
  --exclude 'README.md' \
  "${ROOT}/" "${HOST}:${REMOTE}/"

umask 077
tmp_env="$(mktemp)"
trap 'rm -f "${tmp_env}"' EXIT
cat >"${tmp_env}" <<EOF
GRAFANA_HTTP_PORT=3000
GF_SECURITY_ADMIN_USER=${GRAFANA_ADMIN_USER}
GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD}
GF_SECURITY_ADMIN_EMAIL=${GRAFANA_ADMIN_EMAIL}
GF_SERVER_ROOT_URL=${GRAFANA_URL}
GF_SERVER_DOMAIN=grafana.qa.guru
GF_SECURITY_COOKIE_SECURE=true
GF_SECURITY_STRICT_TRANSPORT_SECURITY=true
GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET=${GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET:-}
EOF
scp -q "${tmp_env}" "${HOST}:${REMOTE}/.env"
ssh "${HOST}" "chmod 600 '${REMOTE}/.env'"

ssh "${HOST}" "cd '${REMOTE}' && if docker network inspect qa-guru-observe >/dev/null 2>&1; then
  echo 'observe network: attach Grafana'
  docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.observe.yml up -d
  docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.observe.yml ps
else
  echo 'observe network: missing (Prometheus not up yet) — Grafana only'
  docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
  docker compose -f docker-compose.yml -f docker-compose.prod.yml ps
fi"

echo "OK: Grafana compose on ${HOST}:${REMOTE}"
