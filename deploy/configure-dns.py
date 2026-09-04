#!/usr/bin/env python3
"""Selectel DNS for grafana.qa.guru.

Default is dry-run. Mutates only with --apply.

  python …/configure-dns.py                  # upsert A grafana.qa.guru → Box2
  python …/configure-dns.py --apply
  python …/configure-dns.py --purge-testing  # drop stale grafana.testing CNAME+TXT
  python …/configure-dns.py --purge-testing --apply
"""
from __future__ import annotations

import argparse
import json
import ssl
import urllib.error
import urllib.request
from pathlib import Path

try:
    import certifi
except ImportError:
    certifi = None  # type: ignore[assignment]

CL21R_ENV = Path.home() / ".config/cl21r.env"
SELECTEL_API_TOKEN = Path.home() / ".config/selectel-api.token"

ZONE = "qa.guru"
FQDN = "grafana.qa.guru"
ZONE_ID = "d36f148a-c0d9-49c6-a712-a1db19c5a986"
PROJECT_ID = "867a0fed571e4ecdae9dc5a73cd99046"
DNS_API = "https://api.selectel.ru/domains/v2"
STALE_TXT = "_external-dns.cname-grafana.qa.guru"
TESTING_FQDN = "grafana.testing.qa.guru"
TESTING_TXT = "_external-dns.cname-grafana.testing.qa.guru"
TTL = 300


def ssl_ctx() -> ssl.SSLContext:
    if certifi is not None:
        return ssl.create_default_context(cafile=certifi.where())
    return ssl.create_default_context()


def http(
    method: str,
    url: str,
    headers: dict,
    body: dict | list | None = None,
) -> tuple[int, dict | list | None]:
    data = None if body is None else json.dumps(body).encode()
    hdr = dict(headers)
    if data is not None and "Content-Type" not in hdr:
        hdr["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=hdr)
    try:
        with urllib.request.urlopen(req, timeout=60, context=ssl_ctx()) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            payload: dict | list | None = json.loads(raw) if raw else None
        except Exception:
            payload = {"raw": raw[:800]}
        return e.code, payload


def project_token() -> str:
    if not SELECTEL_API_TOKEN.is_file():
        raise RuntimeError(f"missing {SELECTEL_API_TOKEN}")
    token = SELECTEL_API_TOKEN.read_text(encoding="utf-8").strip()
    code, data = http(
        "POST",
        "https://api.selectel.ru/vpc/resell/v2/tokens",
        {"X-Token": token, "Accept": "application/json"},
        {"token": {"project_id": PROJECT_ID}},
    )
    if code != 200 or not isinstance(data, dict):
        raise RuntimeError(f"Selectel project token: {code} {data}")
    return data["token"]["id"]


def sel_headers(token: str) -> dict:
    return {"X-Auth-Token": token, "Accept": "application/json"}


def list_rrsets(token: str, zone_id: str) -> list[dict]:
    out: list[dict] = []
    offset = 0
    while True:
        code, data = http(
            "GET",
            f"{DNS_API}/zones/{zone_id}/rrset?limit=1000&offset={offset}",
            sel_headers(token),
        )
        if code != 200 or not isinstance(data, dict):
            raise RuntimeError(f"Selectel rrset: {code} {data}")
        out.extend(data.get("result") or [])
        nxt = data.get("next_offset")
        if not nxt:
            break
        offset = int(nxt)
    return out


def find_rr(rrsets: list[dict], name: str, rtype: str) -> dict | None:
    want = name if name.endswith(".") else name + "."
    for r in rrsets:
        if r.get("name") == want and r.get("type") == rtype:
            return r
    return None


def delete_rr(token: str, zone_id: str, rr: dict, apply: bool) -> dict:
    label = f"{rr.get('type')} {rr.get('name')}"
    if not apply:
        return {"action": "would_delete", "rr": label, "id": rr.get("id")}
    code, data = http(
        "DELETE",
        f"{DNS_API}/zones/{zone_id}/rrset/{rr['id']}",
        sel_headers(token),
    )
    if code not in (200, 204):
        raise RuntimeError(f"Selectel DELETE {label}: {code} {data}")
    return {"action": "deleted", "rr": label, "id": rr.get("id")}


def upsert_a(token: str, zone_id: str, ip: str, apply: bool, rrsets: list[dict]) -> dict:
    name = FQDN + "."
    body = {
        "name": name,
        "ttl": TTL,
        "type": "A",
        "records": [{"content": ip, "disabled": False}],
        "comment": "grafana.qa.guru Box2",
    }
    ex = find_rr(rrsets, name, "A")
    if ex is not None:
        old = sorted(x["content"] for x in ex.get("records") or [])
        if old == [ip] and int(ex.get("ttl") or 0) == TTL:
            return {"action": "noop", "rr": f"A {name}", "ip": ip}
        if not apply:
            return {"action": "would_update", "rr": f"A {name}", "from": old, "to": ip}
        code, data = http(
            "PATCH",
            f"{DNS_API}/zones/{zone_id}/rrset/{ex['id']}",
            sel_headers(token),
            {
                "ttl": TTL,
                "records": [{"content": ip, "disabled": False}],
                "comment": "grafana.qa.guru Box2",
            },
        )
        if code not in (200, 204):
            raise RuntimeError(f"Selectel PATCH A {name}: {code} {data}")
        return {"action": "updated", "rr": f"A {name}", "to": ip}
    if not apply:
        return {"action": "would_create", "rr": f"A {name}", "to": ip}
    code, data = http(
        "POST",
        f"{DNS_API}/zones/{zone_id}/rrset",
        sel_headers(token),
        body,
    )
    if code not in (200, 201):
        raise RuntimeError(f"Selectel POST A {name}: {code} {data}")
    return {"action": "created", "rr": f"A {name}", "to": ip}


def _dotenv(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        out[key.strip()] = value.strip().strip("'").strip('"')
    return out


def box2_ip() -> str:
    ip = _dotenv(CL21R_ENV).get("BOX2_CI", "")
    if not ip or ip == "TBD" or "." not in ip:
        raise RuntimeError("BOX2_CI missing in ~/.config/cl21r.env")
    return ip


def purge_testing(token: str, apply: bool, rrsets: list[dict]) -> list[dict]:
    steps: list[dict] = []
    for name, rtype in ((TESTING_FQDN, "CNAME"), (TESTING_TXT, "TXT")):
        rr = find_rr(rrsets, name, rtype)
        if rr is None:
            steps.append({"action": "noop", "rr": f"{rtype} {name}."})
            continue
        steps.append(delete_rr(token, ZONE_ID, rr, apply))
    return steps


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument(
        "--purge-testing",
        action="store_true",
        help="Delete stale grafana.testing.qa.guru CNAME + TXT; leave grafana.qa.guru A",
    )
    ns = parser.parse_args()
    token = project_token()
    rrsets = list_rrsets(token, ZONE_ID)

    if ns.purge_testing:
        report = {
            "apply": ns.apply,
            "zone": ZONE,
            "mode": "purge-testing",
            "steps": purge_testing(token, ns.apply, rrsets),
        }
        print(json.dumps(report, indent=2))
        return 0

    ip = box2_ip()
    report: dict = {"apply": ns.apply, "zone": ZONE, "fqdn": FQDN, "ip": ip, "steps": []}

    cname = find_rr(rrsets, FQDN, "CNAME")
    if cname is not None:
        report["steps"].append(delete_rr(token, ZONE_ID, cname, ns.apply))
        if ns.apply:
            rrsets = list_rrsets(token, ZONE_ID)

    txt = find_rr(rrsets, STALE_TXT, "TXT")
    if txt is not None:
        report["steps"].append(delete_rr(token, ZONE_ID, txt, ns.apply))

    report["steps"].append(upsert_a(token, ZONE_ID, ip, ns.apply, rrsets))
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
