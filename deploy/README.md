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

## SSO — `oidc.py`

Фаза `11.qa-guru-identity`, [ADR 017](../../../../../docs/adr/017-qa-guru-identity.md), окно [Grafana SSO](../../../../../docs/plans/qa-guru-identity.md#grafana-sso--2026-09-06). Клиент `grafana` живёт в realm-файле `auth-qa-guru-home/dev/realm/qaguru-realm.json`.

```bash
python3 deploy/oidc.py inventory     # 1. гейт: люди + орги + команды + SA вне бокса
python3 deploy/oidc.py dump          # 2. гейт: grafana.db + grafana.ini + .env, sha256 сверен
python3 deploy/oidc.py seed-secret   # 3. секрет клиента → ~/.config/grafana/oidc.env (600)
python3 deploy/oidc.py configure     # 4. деплой grafana.ini + секрета, recreate, health
python3 deploy/oidc.py verify        # 5. приёмка целиком
python3 deploy/oidc.py break-glass   # 6. admin входит при остановленном Keycloak
```

Отдельно: `login-check` (`staff-pilot` / `mentor-pilot` / `student-pilot` из `pilot.env`, не живой `svasenkov`), `probe-staff` (одноразовый человек в `/staff` → Admin, удаляется), `logout-check` (`staff-pilot` / `mentor-pilot`: RP-initiated logout → Keycloak снова спрашивает пароль), `rollback --dump <tar.gz>`. IdP не гасить. Клиент `oauth2-proxy` не трогать.

Что важно знать перед правкой:

- **Секрет живёт только в env.** `grafana.ini` в git несёт всё, кроме `client_secret`; сам секрет — `~/.config/grafana/oidc.env` → `/opt/grafana.qa.guru/.env` (600). `install-box2.sh` перегенерирует `.env` с нуля, поэтому он до-эмитит секрет сам и **отказывается** деплоить, если `grafana.ini` включает `generic_oauth`, а секрета нет. Без этого обычная переустановка молча выключала бы SSO.
- **`login_attribute_path = preferred_username` не трогать.** Grafana по умолчанию читает только `login` / `username`, а Keycloak присылает `preferred_username` — без этой строки login становится email-ом, и канон handle рассыпается.
- **`role_attribute_strict = true` — это и есть запрет для `/students`.** В выражении роли для них нет; уберёшь флаг — все 98 студентов realm-а получат `auto_assign_org_role` (Viewer).
- **`scopes` без `groups`.** В Keycloak нет такого client scope, claim приходит от маппера клиента; запрос scope `groups` даёт `invalid_scope`.
- **`disable_login_form` не включать** — см. § SSO в [README клона](../README.md).
- **`dump` гасит контейнер на несколько секунд.** В образе нет `sqlite3`, а копия работающего файла базы — не дамп.
- **Форму логина Keycloak не переотправлять в цикле.** Realm с brute-force protection считает две попытки в пределах секунды quick-login-атакой и запирает учётку на 60 с; `keycloak_login` шлёт форму один раз и возвращает текст ошибки со страницы.
