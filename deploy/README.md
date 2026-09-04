# Deploy grafana.qa.guru

Bringup Grafana OSS on Box 2. DNS A уже указывает на Box2; скрипт DNS — идемпотентный dry-run.

## Prerequisites

- SSH alias `box2-ci` → `89.248.193.83`
- `~/.config/grafana/admin.env` — `GRAFANA_ADMIN_USER` / `GRAFANA_ADMIN_PASSWORD` / `GRAFANA_ADMIN_EMAIL`
- Docker + nginx + certbot на хосте

## Install order

Из корня клона:

```bash
# 1. compose → /opt/grafana.qa.guru
./deploy/install-box2.sh

# 2. DNS A grafana.qa.guru → Box2 (Selectel; default dry-run)
python3 ./deploy/configure-dns.py
python3 ./deploy/configure-dns.py --apply

# 3. nginx TLS
./deploy/configure-nginx-box2.sh

# 4. smoke
./deploy/smoke.sh
```

Prometheus (отдельный репозиторий) поднимается **рядом**. На Box2 Grafana цепляется к `qa-guru-observe` из `install-box2.sh`, если сеть уже есть. Host-порт Prometheus: **9091**.
