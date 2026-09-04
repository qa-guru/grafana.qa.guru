#!/usr/bin/env bash
# nginx TLS vhost for grafana.qa.guru on Box 2 (proxy → 127.0.0.1:3000).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NGINX_SRC="$(cd "${SCRIPT_DIR}/.." && pwd)/nginx/grafana.qa.guru.nginx"
HOST="${GRAFANA_DEPLOY_HOST:-box2-ci}"

if [[ ! -f "${NGINX_SRC}" ]]; then
  echo "FAIL: ${NGINX_SRC} missing" >&2
  exit 1
fi

ssh "${HOST}" 'bash -s' <<'REMOTE'
set -euo pipefail
sudo tee /etc/nginx/sites-available/grafana >/dev/null <<'HTTPONLY'
server {
    listen 80;
    listen [::]:80;
    server_name grafana.qa.guru;

    location ^~ /.well-known/acme-challenge/ {
        default_type text/plain;
        root /var/www/html;
        try_files $uri =404;
    }

    location / {
        include /etc/nginx/proxy_params;
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
HTTPONLY
sudo ln -sf /etc/nginx/sites-available/grafana /etc/nginx/sites-enabled/grafana
sudo nginx -t && sudo systemctl reload nginx
REMOTE

if ssh "${HOST}" 'test -f /etc/letsencrypt/live/grafana.qa.guru/fullchain.pem'; then
  echo "LE cert already present"
else
  ssh "${HOST}" 'sudo certbot certonly --webroot -w /var/www/html -d grafana.qa.guru --non-interactive --agree-tos -m admin@qa.guru'
fi

scp -q "${NGINX_SRC}" "${HOST}:/tmp/grafana.qa.guru.nginx"
ssh "${HOST}" 'sudo mv /tmp/grafana.qa.guru.nginx /etc/nginx/sites-available/grafana && sudo ln -sf /etc/nginx/sites-available/grafana /etc/nginx/sites-enabled/grafana && sudo nginx -t && sudo systemctl reload nginx'

echo "Box2 nginx grafana.qa.guru + LE configured."
