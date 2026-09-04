# grafana.qa.guru

Production **Grafana OSS** on Box 2 — **https://grafana.qa.guru**

Публичный UI. Метрики собирает соседний репозиторий [prometheus.qa.guru](https://github.com/qa-guru/prometheus.qa.guru) (только loopback). Пароль админа в git **не** кладём.

| | |
|--|--|
| URL | https://grafana.qa.guru |
| Edition | Grafana OSS **13.0.2** (`grafana/grafana-oss:13.0.2`) |
| Host | Box 2 `89.248.193.83` — рядом Jenkins, Sonar |
| Path | `/opt/grafana.qa.guru` |
| Auth | login `admin` · `admin@qa.guru` — пароль локально в `~/.config/grafana/admin.env` |

## Для учащихся

Смотрите, как поднят Grafana: pin образа, `grafana.ini`, file provisioning, nginx → loopback `:3000`.

```bash
git clone https://github.com/qa-guru/grafana.qa.guru.git
cd grafana.qa.guru
cp .env.example .env          # свой пароль, не коммитить
docker compose up -d
curl -sf http://127.0.0.1:3031/api/health
```

Локальный порт **3031**, чтобы не пересечься с Grafana внутри контейнера (`:3000`) и с design-system `:3000`.

Чтобы Grafana увидела Prometheus (имя сервиса `prometheus`):

```bash
docker network create qa-guru-observe 2>/dev/null || true
# сначала поднимите https://github.com/qa-guru/prometheus.qa.guru
docker compose -f docker-compose.yml -f docker-compose.observe.yml up -d
```

Дашборд **Box2 observer** (`box2-observer.json`) — CPU/RAM/load. **Load SUT observer** (`load-sut-observer.json`, datasource `load-sut`) — node-exporter на load-VM. **ollama.qa.guru GPU** (`ollama-gpu.json`) — VRAM / loaded models / exporter. На Box2 Prometheus снаружи `:9091` (host `:9090` = selenoid-warm-pool).

## Структура

| Путь | Назначение |
|------|------------|
| [`docker-compose.yml`](docker-compose.yml) | Grafana OSS, loopback publish, volume sqlite |
| [`docker-compose.prod.yml`](docker-compose.prod.yml) | `restart: unless-stopped` |
| [`docker-compose.observe.yml`](docker-compose.observe.yml) | сеть `qa-guru-observe` → Prometheus |
| [`grafana.ini`](grafana.ini) | domain, root_url, без sign-up |
| [`provisioning/`](provisioning/) | datasources (Testdata + Box2 Prometheus + **load-sut**) и dashboards |
| [`nginx/grafana.qa.guru.nginx`](nginx/grafana.qa.guru.nginx) | TLS vhost, websockets |
| [`deploy/`](deploy/) | Box2 install / nginx / DNS / smoke |

Секреты (не в git): `~/.config/grafana/admin.env`.

Monorepo wrapper: `projects/services-home/grafana-qa-guru-home/`.
