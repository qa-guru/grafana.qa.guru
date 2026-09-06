#!/usr/bin/env python3
"""Grafana SSO — generic_oauth against https://auth.qa.guru (phase 11.qa-guru-identity).

Grafana OSS has role_attribute_path (JMESPath) but no Team Sync (Enterprise), so roles come
from the groups claim and Grafana teams stay manual. /students is denied by role_attribute_strict.

Secrets live in ~/.config/grafana (mode 600) and in /opt/grafana.qa.guru/.env (600) on Box2.
Nothing secret is printed.

  python3 deploy/oidc.py inventory     # gate: users + orgs + teams + service accounts, off-box
  python3 deploy/oidc.py dump          # gate: grafana.db + grafana.ini snapshot before the change
  python3 deploy/oidc.py seed-secret   # client secret + post-logout redirect on the Keycloak side
  python3 deploy/oidc.py configure     # deploy grafana.ini + secret, recreate, wait for health
  python3 deploy/oidc.py login-check   # real sign-in with the pilot people
  python3 deploy/oidc.py probe-staff   # /staff → Admin on a disposable person, then remove it
  python3 deploy/oidc.py logout-check  # RP-initiated logout lands back on the Grafana login page
  python3 deploy/oidc.py verify        # acceptance
  python3 deploy/oidc.py break-glass   # local admin + API with Keycloak stopped
  python3 deploy/oidc.py rollback      # back to the dumped grafana.ini (dumps current first)
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any

try:
    import certifi
except ImportError:
    certifi = None  # type: ignore[assignment]

GRAFANA_URL = os.environ.get("GRAFANA_URL", "https://grafana.qa.guru").rstrip("/")
AUTH_URL = os.environ.get("AUTH_URL", "https://auth.qa.guru").rstrip("/")
REALM = os.environ.get("REALM", "qaguru")
CLIENT_ID = "grafana"
BOX2 = os.environ.get("GRAFANA_SSH", "box2-ci")
AUTH_HOST = os.environ.get("AUTH_SSH", "auth-qa-guru")
KEYCLOAK_CONTAINER = os.environ.get("KEYCLOAK_CONTAINER", "auth-qa-guru-keycloak-1")
REMOTE = "/opt/grafana.qa.guru"
GRAFANA_CONTAINER = os.environ.get("GRAFANA_CONTAINER", "grafanaqaguru-grafana-1")
DATA_VOLUME = "grafanaqaguru_grafana_data"

ADMIN_ENV_FILE = Path(os.environ.get("GRAFANA_ADMIN_ENV", Path.home() / ".config/grafana/admin.env"))
OIDC_ENV_FILE = Path(os.environ.get("GRAFANA_OIDC_ENV", Path.home() / ".config/grafana/oidc.env"))
AUTH_ENV_FILE = Path(os.environ.get("AUTH_ENV", Path.home() / ".config/auth-qa-guru/keycloak.env"))
PILOT_ENV_FILE = Path(os.environ.get("PILOT_ENV", Path.home() / ".config/auth-qa-guru/pilot.env"))
TEACHERS_ENV_FILE = Path(os.environ.get("GRAFANA_TEACHERS_ENV", Path.home() / ".config/grafana/load-teachers.env"))
INV_DIR = Path.home() / ".config/grafana/sso-inventory"

ISSUER = f"{AUTH_URL}/realms/{REALM}"
REDIRECT_URI = f"{GRAFANA_URL}/login/generic_oauth"
POST_LOGOUT_URI = f"{GRAFANA_URL}/login"
SIGNOUT_URL = (
    f"{ISSUER}/protocol/openid-connect/logout?client_id={CLIENT_ID}"
    f"&post_logout_redirect_uri={urllib.parse.quote(POST_LOGOUT_URI, safe='')}"
)

# Break-glass: the local admin must survive every realm swap (ADR 017).
BREAK_GLASS = {"admin"}
# Load-course teachers: logins are GetCourse emails, not handles, and they are not in Keycloak.
# They keep the password form — which is why disable_login_form stays false.
LOCAL_TEACHERS = {"venam1204@gmail.com", "suslovdeniss59@gmail.com"}

# group → Grafana role. Anything else falls through and role_attribute_strict denies the login.
ROLE_BY_GROUP = {"/staff": "Admin", "/mentors": "Viewer"}
ROLE_ATTRIBUTE_PATH = (
    "contains(groups[*], '/staff') && 'Admin' || contains(groups[*], '/mentors') && 'Viewer'"
)


# ---------------------------------------------------------------------------
# plumbing
# ---------------------------------------------------------------------------


def ssl_ctx() -> ssl.SSLContext:
    if certifi is not None:
        return ssl.create_default_context(cafile=certifi.where())
    return ssl.create_default_context()


def load_kv(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.is_file():
        return env
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        env[key.strip()] = value.strip()
    return env


def ssh(host: str, script: str, *, check: bool = True, timeout: int = 900) -> str:
    proc = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20", host, "bash", "-s"],
        input=script.encode(),
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    out = (proc.stdout or b"").decode("utf-8", "replace")
    if check and proc.returncode != 0:
        err = (proc.stderr or b"").decode("utf-8", "replace")[:1200]
        raise SystemExit(f"ssh {host} failed ({proc.returncode}): {err or out[:600]}")
    return out


def admin_env() -> dict[str, str]:
    env = load_kv(ADMIN_ENV_FILE)
    missing = [k for k in ("GRAFANA_ADMIN_USER", "GRAFANA_ADMIN_PASSWORD") if not env.get(k)]
    if missing:
        raise SystemExit(f"missing {', '.join(missing)} in {ADMIN_ENV_FILE}")
    return env


def gapi(path: str, method: str = "GET", body: Any = None) -> Any:
    """Grafana API as the local admin (basic auth — independent of the OAuth provider)."""
    env = admin_env()
    token = base64.b64encode(f"{env['GRAFANA_ADMIN_USER']}:{env['GRAFANA_ADMIN_PASSWORD']}".encode()).decode()
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Authorization": f"Basic {token}"}
    if data:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"{GRAFANA_URL}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30, context=ssl_ctx()) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"{method} {path} -> {exc.code} {exc.read()[:300]!r}") from exc


def auth_env() -> dict[str, str]:
    env = load_kv(AUTH_ENV_FILE)
    missing = [
        k
        for k in ("KC_BOOTSTRAP_ADMIN_USERNAME", "KC_BOOTSTRAP_ADMIN_PASSWORD", "KC_CLIENT_SECRET_GRAFANA")
        if not env.get(k)
    ]
    if missing:
        raise SystemExit(f"missing {', '.join(missing)} in {AUTH_ENV_FILE}")
    return env


def keycloak_token(env: dict[str, str]) -> str:
    form = urllib.parse.urlencode(
        {
            "client_id": "admin-cli",
            "grant_type": "password",
            "username": env["KC_BOOTSTRAP_ADMIN_USERNAME"],
            "password": env["KC_BOOTSTRAP_ADMIN_PASSWORD"],
        }
    ).encode()
    req = urllib.request.Request(f"{AUTH_URL}/realms/master/protocol/openid-connect/token", data=form, method="POST")
    with urllib.request.urlopen(req, timeout=30, context=ssl_ctx()) as resp:
        return json.loads(resp.read())["access_token"]


def kc(method: str, path: str, token: str, body: Any = None) -> Any:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Authorization": f"Bearer {token}"}
    if data:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"{AUTH_URL}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30, context=ssl_ctx()) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"{method} {path} -> {exc.code} {exc.read()[:300]!r}") from exc


def kc_group_members(token: str, name: str) -> list[str]:
    groups = kc("GET", f"/admin/realms/{REALM}/groups?search={name}", token) or []
    match = next((g for g in groups if g["name"] == name), None)
    if match is None:
        return []
    members = kc("GET", f"/admin/realms/{REALM}/groups/{match['id']}/members?briefRepresentation=true&max=1000", token)
    return sorted(u["username"] for u in members or [])


# ---------------------------------------------------------------------------
# gate 1 — inventory (users + orgs + teams + service accounts), off-box
# ---------------------------------------------------------------------------


def classify(user: dict[str, Any]) -> tuple[str, str]:
    login = user["login"]
    if login in BREAK_GLASS:
        return "break-glass", "local admin; never federated; keeps the password form"
    if login in LOCAL_TEACHERS:
        return "local-teacher", "login is a GetCourse email, absent from Keycloak; stays local"
    return "review", "decide in the window before federating"


def cmd_inventory() -> int:
    users = gapi("/api/users?perpage=500")
    orgs = gapi("/api/orgs")
    org_users = gapi("/api/org/users")
    teams = gapi("/api/teams/search?perpage=500")
    service_accounts = gapi("/api/serviceaccounts/search?perpage=500")
    datasources = gapi("/api/datasources")
    health = gapi("/api/health")
    try:  # legacy API keys are gone in Grafana 11+, the endpoint answers 404
        api_keys: Any = gapi("/api/auth/keys")
    except RuntimeError as exc:
        api_keys = {"unavailable": str(exc)[:120]}

    role_by_login = {u["login"]: u["role"] for u in org_users}
    token = keycloak_token(auth_env())
    kc_groups = {name: kc_group_members(token, name) for name in ("staff", "mentors", "students")}
    kc_by_email: dict[str, list[str]] = {}
    kc_logins: set[str] = set()
    for name, members in kc_groups.items():
        kc_logins.update(members)
    for user in users:  # P5 lesson: compare emails, not just counts
        found = kc("GET", f"/admin/realms/{REALM}/users?email={urllib.parse.quote(user['email'])}&exact=true", token)
        kc_by_email[user["email"]] = [u["username"] for u in found or []]

    mapping = []
    for user in users:
        kind, note = classify(user)
        mapping.append(
            {
                "grafana_id": user["id"],
                "login": user["login"],
                "email": user["email"],
                "name": user["name"],
                "org_role": role_by_login.get(user["login"]),
                "grafana_admin": user["isAdmin"],
                "auth_labels": user["authLabels"],
                "keycloak_username_match": user["login"] in kc_logins,
                "keycloak_email_match": kc_by_email.get(user["email"], []),
                "decision": kind,
                "note": note,
            }
        )

    snapshot = {
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "grafana_url": GRAFANA_URL,
        "version": (health or {}).get("version"),
        "counts": {
            "users": len(users),
            "orgs": len(orgs),
            "teams": teams.get("totalCount", 0),
            "service_accounts": service_accounts.get("totalCount", 0),
            "datasources": len(datasources),
        },
        "users": users,
        "orgs": orgs,
        "org_users": org_users,
        "teams": teams,
        "service_accounts": service_accounts,
        "api_keys": api_keys,
        "datasources": [{"id": d["id"], "name": d["name"], "type": d["type"], "url": d["url"]} for d in datasources],
        "keycloak_groups": {k: {"count": len(v), "members": v} for k, v in kc_groups.items()},
        "login_to_handle": mapping,
    }

    INV_DIR.mkdir(parents=True, exist_ok=True)
    INV_DIR.chmod(0o700)
    path = INV_DIR / "before.json"
    path.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False), encoding="utf-8")
    path.chmod(0o600)

    print(f"Grafana {snapshot['version']} — {GRAFANA_URL}")
    print(
        f"users {len(users)} · orgs {len(orgs)} · teams {teams.get('totalCount', 0)} · "
        f"service accounts {service_accounts.get('totalCount', 0)} · datasources {len(datasources)}"
    )
    print(f"api keys: {api_keys if isinstance(api_keys, dict) else len(api_keys)}")
    print("\nlogin → handle:")
    for row in mapping:
        flag = "kc:" + (",".join(row["keycloak_email_match"]) or "-")
        print(
            f"  {row['login']:<28} {row['org_role'] or '-':<7} grafana_admin={str(row['grafana_admin']):<5} "
            f"{row['decision']:<14} {flag}"
        )
        print(f"      {row['note']}")
    print("\nKeycloak groups: " + " · ".join(f"{k} {len(v)}" for k, v in kc_groups.items()))
    print(f"\noff-box snapshot: {path}")
    return 0


# ---------------------------------------------------------------------------
# gate 2 — dump before the change
# ---------------------------------------------------------------------------

DUMP_SCRIPT = r"""
set -euo pipefail
STAMP="$1"
OUT="/tmp/grafana-sso-dump-${STAMP}"
mkdir -p "${OUT}"
cp /opt/grafana.qa.guru/grafana.ini "${OUT}/grafana.ini.before"
sudo cp /opt/grafana.qa.guru/.env "${OUT}/env.before"
# Stop the container for the DB copy: a live sqlite file copy is not a dump.
sudo docker stop CONTAINER >/dev/null
sudo tar czf "${OUT}/grafana_data.tar.gz" -C /var/lib/docker/volumes/VOLUME/_data .
sudo docker start CONTAINER >/dev/null
sudo chown -R "$(id -u):$(id -g)" "${OUT}"
chmod 600 "${OUT}"/*
tar czf "/tmp/grafana-sso-dump-${STAMP}.tar.gz" -C /tmp "grafana-sso-dump-${STAMP}"
rm -rf "${OUT}"
sha256sum "/tmp/grafana-sso-dump-${STAMP}.tar.gz" | awk '{print $1}'
"""


def cmd_dump() -> int:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    script = DUMP_SCRIPT.replace("CONTAINER", GRAFANA_CONTAINER).replace("VOLUME", DATA_VOLUME)
    out = ssh(BOX2, f"bash -s -- {stamp} <<'SH'\n{script}\nSH\n")
    remote_sha = out.strip().splitlines()[-1].strip()
    remote_file = f"/tmp/grafana-sso-dump-{stamp}.tar.gz"

    INV_DIR.mkdir(parents=True, exist_ok=True)
    INV_DIR.chmod(0o700)
    local = INV_DIR / f"grafana-sso-dump-{stamp}.tar.gz"
    subprocess.run(["scp", "-q", f"{BOX2}:{remote_file}", str(local)], check=True)
    local.chmod(0o600)
    local_sha = hashlib.sha256(local.read_bytes()).hexdigest()
    if local_sha != remote_sha:
        raise SystemExit(f"sha256 mismatch: box2={remote_sha} local={local_sha}")

    health = gapi("/api/health")
    print(f"dump   {local} ({local.stat().st_size} bytes)")
    print(f"sha256 {local_sha} — matches Box2")
    print(f"kept on Box2: {remote_file}")
    print(f"Grafana back up: database={health.get('database')} version={health.get('version')}")
    return 0


# ---------------------------------------------------------------------------
# Keycloak side — client secret + post-logout redirect
# ---------------------------------------------------------------------------


def cmd_seed_secret() -> int:
    env = auth_env()
    token = keycloak_token(env)
    clients = kc("GET", f"/admin/realms/{REALM}/clients?clientId={CLIENT_ID}", token) or []
    if not clients:
        raise SystemExit(f"client {CLIENT_ID} missing in realm {REALM}")
    client = clients[0]

    wanted = env["KC_CLIENT_SECRET_GRAFANA"]
    if client.get("secret") != wanted:
        raise SystemExit(
            f"client secret in Keycloak differs from KC_CLIENT_SECRET_GRAFANA in {AUTH_ENV_FILE};"
            " realm placeholders are only substituted on --import-realm (P1 lesson)"
        )
    if REDIRECT_URI not in (client.get("redirectUris") or []):
        raise SystemExit(f"redirect uri {REDIRECT_URI} not registered on the client")

    # RP-initiated logout has to be allowed explicitly, otherwise Keycloak shows an error page
    # instead of sending the person back to the Grafana login form.
    attrs = dict(client.get("attributes") or {})
    if attrs.get("post.logout.redirect.uris") != POST_LOGOUT_URI:
        attrs["post.logout.redirect.uris"] = POST_LOGOUT_URI
        kc("PUT", f"/admin/realms/{REALM}/clients/{client['id']}", token, {**client, "attributes": attrs})
        print(f"OK   post.logout.redirect.uris = {POST_LOGOUT_URI}")
    else:
        print(f"OK   post.logout.redirect.uris already {POST_LOGOUT_URI}")

    OIDC_ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    body = (
        "# Grafana generic_oauth client secret (phase 11.qa-guru-identity).\n"
        "# Mirror of KC_CLIENT_SECRET_GRAFANA. Mode 600, never git, never Vault (ADR 017 §12).\n"
        f"GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET={wanted}\n"
    )
    OIDC_ENV_FILE.write_text(body, encoding="utf-8")
    OIDC_ENV_FILE.chmod(0o600)
    print(f"OK   {OIDC_ENV_FILE} (600) — secret sha256[:8]={hashlib.sha256(wanted.encode()).hexdigest()[:8]}")
    print(f"OK   client {CLIENT_ID}: confidential={not client['publicClient']} redirect={REDIRECT_URI}")
    return 0


# ---------------------------------------------------------------------------
# configure — deploy grafana.ini + secret through install-box2.sh
# ---------------------------------------------------------------------------


def wait_health(timeout: int = 120) -> dict[str, Any]:
    deadline = time.time() + timeout
    last: Exception | None = None
    while time.time() < deadline:
        try:
            health = gapi("/api/health")
            if health.get("database") == "ok":
                return health
        except Exception as exc:  # noqa: BLE001 — restart window
            last = exc
        time.sleep(3)
    raise SystemExit(f"grafana did not come back healthy in {timeout}s: {last}")


def cmd_configure() -> int:
    root = Path(__file__).resolve().parent.parent
    ini = (root / "grafana.ini").read_text(encoding="utf-8")
    if "[auth.generic_oauth]" not in ini:
        raise SystemExit("grafana.ini has no [auth.generic_oauth] block — nothing to deploy")
    if not OIDC_ENV_FILE.is_file():
        raise SystemExit(f"{OIDC_ENV_FILE} missing — run seed-secret first")

    subprocess.run([str(root / "deploy" / "install-box2.sh")], check=True, cwd=root)
    health = wait_health()
    print(f"health database={health['database']} version={health['version']}")

    settings = gapi("/api/admin/settings")
    oauth = settings.get("auth.generic_oauth", {})
    print(f"enabled={oauth.get('enabled')} strict={oauth.get('role_attribute_strict')} "
          f"login_attribute_path={oauth.get('login_attribute_path')}")
    print(f"scopes={oauth.get('scopes')!r}")
    print(f"role_attribute_path={oauth.get('role_attribute_path')!r}")
    return 0


# ---------------------------------------------------------------------------
# login / logout checks
# ---------------------------------------------------------------------------


class FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, Any]] = []
        self._current: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k: (v or "") for k, v in attrs}
        if tag == "form":
            self._current = {"action": ad.get("action", ""), "id": ad.get("id", ""), "inputs": {}}
            self.forms.append(self._current)
        elif tag in {"input", "button"} and self._current is not None:
            name = ad.get("name")
            if name:
                self._current["inputs"][name] = ad.get("value", "")


class Session:
    """Cookie-jar browser good enough for the OAuth redirect dance."""

    def __init__(self) -> None:
        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl_ctx()),
            urllib.request.HTTPCookieProcessor(self.jar),
        )
        self.opener.addheaders = [("User-Agent", "qa-guru-grafana-sso/1.0")]

    def fetch(self, url: str, data: bytes | None = None, headers: dict[str, str] | None = None) -> tuple[str, str, int]:
        req = urllib.request.Request(url, data=data, headers=headers or {}, method="POST" if data else "GET")
        try:
            with self.opener.open(req, timeout=45) as resp:
                return resp.geturl(), resp.read().decode("utf-8", "replace"), resp.status
        except urllib.error.HTTPError as exc:
            return url, exc.read().decode("utf-8", "replace"), exc.code
        except urllib.error.URLError as exc:  # IdP host unreachable during the break-glass test
            return url, f"transport error: {exc.reason}", 0

    def cookie(self, name: str) -> str | None:
        return next((c.value for c in self.jar if c.name == name), None)

    def api(self, path: str) -> tuple[int, Any]:
        cookies = "; ".join(f"{c.name}={c.value}" for c in self.jar)
        req = urllib.request.Request(f"{GRAFANA_URL}{path}", headers={"Cookie": cookies})
        try:
            with urllib.request.urlopen(req, timeout=20, context=ssl_ctx()) as resp:
                return resp.status, json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as exc:
            return exc.code, None


def kc_form_error(page: str) -> str | None:
    """Pull the error Keycloak rendered on the login form.

    The text sits in a <span> nested inside the id="input-error-*" div, so a naive
    `id="input-error…">(.*?)<` capture returns whitespace and looks like "no error".
    """
    for pattern in (
        r'kc-feedback-text[^>]*>(.*?)</span>',
        r'id="input-error[^"]*"[^>]*>(.*?)</div>',
        r'id="kc-error-message".*?<p[^>]*>(.*?)</p>',
    ):
        for match in re.finditer(pattern, page, re.S):
            text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", match.group(1))).strip()
            if text:
                return text
    return None


def keycloak_login(sess: Session, url: str, page: str, username: str, password: str) -> tuple[str, str, int]:
    """Submit the Keycloak login form exactly once.

    Never retry: the realm has brute-force protection, and two form posts within a second trip
    the quick-login detector, which locks the account for 60s and hides the real error behind a
    second login page. One attempt plus the rendered error message is both safer and clearer.
    """
    parser = FormParser()
    parser.feed(page)
    form = next((f for f in parser.forms if f["id"] == "kc-form-login" or "username" in f["inputs"]), None)
    if form is None:
        return url, page, 0
    payload = dict(form["inputs"])
    payload["username"] = username
    payload["password"] = password
    payload.setdefault("credentialId", "")
    return sess.fetch(urllib.parse.urljoin(url, form["action"]), urllib.parse.urlencode(payload).encode())


def oidc_login(username: str, password: str) -> dict[str, Any]:
    sess = Session()
    url, page, _ = sess.fetch(f"{GRAFANA_URL}/login/generic_oauth")
    url, page, status = keycloak_login(sess, url, page, username, password)
    code, me = sess.api("/api/user")
    _, orgs = sess.api("/api/user/orgs")
    role = (orgs or [{}])[0].get("role") if isinstance(orgs, list) and orgs else None
    error = None
    raw_error = sess.cookie("login_error")
    if raw_error:
        error = urllib.parse.unquote_plus(raw_error)
    elif code != 200:
        # Two different rejections land here: Keycloak refusing the credentials (error rendered on
        # its form) and Grafana refusing the person after a successful Keycloak login, which is what
        # role_attribute_strict does — it leaves no message in the page, only in the server log.
        error = kc_form_error(page) or (
            "rejected at the Grafana callback: role_attribute_strict_violation"
            if url.startswith(GRAFANA_URL)
            else "no error text; check the Grafana log"
        )
    return {
        "username": username,
        "landed": url,
        "http": status,
        "api_code": code,
        "grafana_login": (me or {}).get("login"),
        "grafana_email": (me or {}).get("email"),
        "grafana_admin": (me or {}).get("isGrafanaAdmin"),
        "org_role": role,
        "error": error,
        "session": sess,
    }


def pilots() -> list[tuple[str, str, str, str | None]]:
    env = load_kv(PILOT_ENV_FILE)
    rows = [
        ("staff", "PILOT_STAFF_USERNAME", "PILOT_STAFF_PASSWORD", "Admin"),
        ("mentors", "PILOT_MENTOR_USERNAME", "PILOT_MENTOR_PASSWORD", "Viewer"),
        ("students", "PILOT_STUDENT_USERNAME", "PILOT_STUDENT_PASSWORD", None),
    ]
    out = []
    for kind, ukey, pkey, expect in rows:
        if env.get(ukey) and env.get(pkey):
            out.append((kind, env[ukey], env[pkey], expect))
    if not out:
        raise SystemExit(f"no pilot credentials in {PILOT_ENV_FILE}")
    return out


def cmd_login_check() -> int:
    rc = 0
    for kind, user, password, expect in pilots():
        res = oidc_login(user, password)
        if expect is None:  # /students must not get in at all
            ok = res["api_code"] != 200
            print(f"{'OK  ' if ok else 'FAIL'} {kind:<9} {user} → denied={ok} api={res['api_code']}")
            if res["error"]:
                print(f"       error: {res['error'][:150]}")
        else:
            ok = res["api_code"] == 200 and res["org_role"] == expect and res["grafana_login"] == user
            print(
                f"{'OK  ' if ok else 'FAIL'} {kind:<9} {user} → login={res['grafana_login']} "
                f"role={res['org_role']} (want {expect}) grafana_admin={res['grafana_admin']}"
            )
        if not ok:
            print(f"       landed={res['landed']} http={res['http']} error={res['error']}")
            rc = 1
    return rc


PROBE_USER = "grafana-staff-probe"


def kc_delete_user(token: str, username: str) -> None:
    found = kc("GET", f"/admin/realms/{REALM}/users?username={username}&exact=true", token) or []
    for user in found:
        kc("DELETE", f"/admin/realms/{REALM}/users/{user['id']}", token)


def grafana_delete_user(login: str) -> bool:
    users = gapi("/api/users?perpage=500")
    match = next((u for u in users if u["login"] == login), None)
    if match is None:
        return False
    gapi(f"/api/admin/users/{match['id']}", method="DELETE")
    return True


def probe_staff(keep: bool = False) -> dict[str, Any]:
    """Prove /staff → Admin with a disposable person, then remove every trace.

    Uses a probe rather than the real staff pilot so acceptance does not depend on the password
    stored in pilot.env, and so the JIT path for a brand-new staff member is exercised too.
    """
    env = auth_env()
    token = keycloak_token(env)
    password = base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")
    kc_delete_user(token, PROBE_USER)
    grafana_delete_user(PROBE_USER)
    kc(
        "POST",
        f"/admin/realms/{REALM}/users",
        token,
        {
            "username": PROBE_USER,
            "enabled": True,
            "email": f"{PROBE_USER}@qa.guru",
            "emailVerified": True,  # P4 lesson: without a verified profile Keycloak 26 stalls on VERIFY_PROFILE
            "firstName": "Grafana",
            "lastName": "Staff Probe",
            "credentials": [{"type": "password", "value": password, "temporary": False}],
        },
    )
    user_id = (kc("GET", f"/admin/realms/{REALM}/users?username={PROBE_USER}&exact=true", token) or [])[0]["id"]
    groups = kc("GET", f"/admin/realms/{REALM}/groups?search=staff", token) or []
    staff = next(g for g in groups if g["name"] == "staff")
    kc("PUT", f"/admin/realms/{REALM}/users/{user_id}/groups/{staff['id']}", token)

    res = oidc_login(PROBE_USER, password)
    res["cleaned"] = False
    if not keep:
        res["cleaned"] = grafana_delete_user(PROBE_USER)
        kc_delete_user(token, PROBE_USER)
    return res


def cmd_probe_staff(keep: bool = False) -> int:
    res = probe_staff(keep)
    ok = res["api_code"] == 200 and res["org_role"] == "Admin" and res["grafana_login"] == PROBE_USER
    print(
        f"{'OK  ' if ok else 'FAIL'} /staff probe → login={res['grafana_login']} role={res['org_role']} "
        f"grafana_admin={res['grafana_admin']}"
    )
    if not ok:
        print(f"       landed={res['landed']} api={res['api_code']} error={res['error']}")
    print(f"     cleanup: grafana user removed={res['cleaned']}, keycloak probe removed={not keep}")
    return 0 if ok else 1


def cmd_logout_check() -> int:
    kind, user, password, _ = pilots()[0]
    res = oidc_login(user, password)
    if res["api_code"] != 200:
        raise SystemExit(f"{user} could not sign in, logout check is meaningless: {res['error']}")
    sess: Session = res["session"]
    url, page, status = sess.fetch(f"{GRAFANA_URL}/logout")
    on_login = url.startswith(POST_LOGOUT_URI) or url.rstrip("/").endswith("/login")
    code, _ = sess.api("/api/user")
    print(f"{'OK  ' if on_login else 'FAIL'} logout landed on {url} (http {status})")
    print(f"{'OK  ' if code != 200 else 'FAIL'} grafana session gone (api/user {code})")
    # The Keycloak session must be gone too, otherwise the next click signs the person back in silently.
    fresh = Session()
    _, page2, _ = fresh.fetch(f"{GRAFANA_URL}/login/generic_oauth")
    asks_password = "kc-form-login" in page2 or 'name="password"' in page2
    print(f"{'OK  ' if asks_password else 'FAIL'} Keycloak asks for credentials again")
    return 0 if (on_login and code != 200 and asks_password) else 1


# ---------------------------------------------------------------------------
# acceptance
# ---------------------------------------------------------------------------


def cmd_verify() -> int:
    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        print(f"{'OK  ' if ok else 'FAIL'} {name}{(' — ' + detail) if detail else ''}")
        if not ok:
            failures.append(name)

    before_path = INV_DIR / "before.json"
    if not before_path.is_file():
        raise SystemExit(f"no {before_path} — run inventory before verifying")
    before = json.loads(before_path.read_text(encoding="utf-8"))

    health = gapi("/api/health")
    check("grafana healthy", health.get("database") == "ok", f"version {health.get('version')}")
    check("version unchanged", health.get("version") == before["version"], str(before["version"]))

    users = gapi("/api/users?perpage=500")
    floor = before["counts"]["users"]
    check("users did not shrink", len(users) >= floor, f"{floor} → {len(users)}")

    by_login = {u["login"]: u for u in users}
    org_users = {u["login"]: u for u in gapi("/api/org/users")}

    for login in sorted(BREAK_GLASS):
        user = by_login.get(login)
        check(
            f"break-glass {login} intact",
            bool(user) and user["isAdmin"] and not user["authLabels"],
            f"grafana_admin={bool(user and user['isAdmin'])} auth_labels={user['authLabels'] if user else '-'}",
        )

    for login in sorted(LOCAL_TEACHERS):
        was = next((u for u in before["users"] if u["login"] == login), None)
        now = by_login.get(login)
        same = bool(was and now) and was["id"] == now["id"] and was["email"] == now["email"]
        role_same = org_users.get(login, {}).get("role") == next(
            (u["role"] for u in before["org_users"] if u["login"] == login), None
        )
        check(
            f"local teacher {login} untouched",
            same and role_same and not (now or {}).get("authLabels"),
            f"id/email stable={same} role={org_users.get(login, {}).get('role')}",
        )

    # The teachers are the reason the password form stays: prove they can still get in.
    teachers = load_kv(TEACHERS_ENV_FILE)
    for prefix in ("MARAT", "DENIS"):
        login, password = teachers.get(f"{prefix}_LOGIN"), teachers.get(f"{prefix}_PASSWORD")
        if not (login and password):
            continue
        code, got = form_login(login, password)
        check(
            f"teacher {login} still signs in with the form",
            code == 200 and got == login,
            f"api/user {code}",
        )

    teams = gapi("/api/teams/search?perpage=500")
    check(
        "no Team Sync invented (teams unchanged)",
        teams.get("totalCount", 0) == before["counts"]["teams"],
        f"{before['counts']['teams']} → {teams.get('totalCount', 0)}",
    )

    settings = gapi("/api/admin/settings")
    oauth = settings.get("auth.generic_oauth", {})
    auth = settings.get("auth", {})
    check("generic_oauth enabled", oauth.get("enabled") == "true")
    check("client_id = grafana", oauth.get("client_id") == CLIENT_ID, oauth.get("client_id", "-"))
    check("client_secret present", bool(oauth.get("client_secret")), "redacted by the settings API")
    check(
        "scopes without groups (no such client scope in Keycloak)",
        oauth.get("scopes") == "openid profile email",
        repr(oauth.get("scopes")),
    )
    check(
        "login_attribute_path = preferred_username",
        oauth.get("login_attribute_path") == "preferred_username",
        "otherwise Grafana logins become emails, not handles",
    )
    check(
        "role_attribute_path maps /staff and /mentors",
        oauth.get("role_attribute_path") == ROLE_ATTRIBUTE_PATH,
        repr(oauth.get("role_attribute_path")),
    )
    check("role_attribute_strict = true", oauth.get("role_attribute_strict") == "true", "/students has no role → denied")
    check("skip_org_role_sync = false", oauth.get("skip_org_role_sync") == "false")
    check(
        "allow_assign_grafana_admin = false",
        oauth.get("allow_assign_grafana_admin") == "false",
        "server admin stays on the break-glass account",
    )
    check("issuer is auth.qa.guru", ISSUER in (oauth.get("auth_url") or ""), oauth.get("auth_url", "-"))
    check("disable_login_form = false", auth.get("disable_login_form") == "false", "break-glass + local teachers")
    check(
        "oauth_allow_insecure_email_lookup = false",
        auth.get("oauth_allow_insecure_email_lookup") == "false",
        "identity by IdP subject, not by email",
    )
    check("basic auth still on for scripts", settings.get("auth.basic", {}).get("enabled") == "true")

    print()
    users_before_probe = len(users)
    probe = probe_staff()
    check(
        "/staff → Admin (disposable probe, JIT)",
        probe["api_code"] == 200 and probe["org_role"] == "Admin" and probe["grafana_login"] == PROBE_USER,
        f"login={probe['grafana_login']} role={probe['org_role']} grafana_admin={probe['grafana_admin']}",
    )
    check(
        "/staff is org Admin, not server admin",
        probe["grafana_admin"] is False,
        "allow_assign_grafana_admin = false",
    )
    check("probe cleaned up", len(gapi("/api/users?perpage=500")) == users_before_probe, f"{users_before_probe} users")

    for kind, user, password, expect in pilots():
        if kind == "staff":
            continue  # covered by the probe above
        res = oidc_login(user, password)
        if expect is None:
            check(f"{kind} {user} denied", res["api_code"] != 200, (res["error"] or "")[:90])
        else:
            check(
                f"{kind} {user} → {expect}",
                res["api_code"] == 200 and res["org_role"] == expect and res["grafana_login"] == user,
                f"login={res['grafana_login']} role={res['org_role']} grafana_admin={res['grafana_admin']}",
            )

    prom = ssh(
        BOX2,
        "set -euo pipefail\nsudo ss -ltnp 2>/dev/null | grep -E ':9091' || echo none\n",
    ).strip()
    check("Prometheus still loopback on Box2", "127.0.0.1:9091" in prom and "0.0.0.0:9091" not in prom, prom.splitlines()[0][:90] if prom else "-")

    print()
    print(f"{len(failures)} failure(s)" if failures else "acceptance: all checks green")
    return 1 if failures else 0


# ---------------------------------------------------------------------------
# break-glass
# ---------------------------------------------------------------------------


def _keycloak(action: str) -> None:
    # P2b lesson: only `docker stop/start` the container — keycloak.service is a oneshot unit
    # and `systemctl start` after stopping the container is a no-op.
    ssh(AUTH_HOST, f"set -euo pipefail\nsudo docker {action} {KEYCLOAK_CONTAINER} >/dev/null\n")


def form_login(user: str, password: str) -> tuple[int, str | None]:
    sess = Session()
    url, page, status = sess.fetch(
        f"{GRAFANA_URL}/login",
        json.dumps({"user": user, "password": password}).encode(),
        {"Content-Type": "application/json"},
    )
    code, me = sess.api("/api/user")
    return code, (me or {}).get("login")


def cmd_break_glass() -> int:
    rc = 0
    env = admin_env()
    print(f"stopping {KEYCLOAK_CONTAINER} on {AUTH_HOST}")
    _keycloak("stop")
    try:
        time.sleep(3)
        code, login = form_login(env["GRAFANA_ADMIN_USER"], env["GRAFANA_ADMIN_PASSWORD"])
        ok = code == 200 and login == env["GRAFANA_ADMIN_USER"]
        print(f"{'OK  ' if ok else 'FAIL'} password form: {login} (api/user {code})")
        rc |= 0 if ok else 1

        users = gapi("/api/users?perpage=5")
        print(f"{'OK  ' if users else 'FAIL'} basic-auth API: {len(users)} users readable")
        rc |= 0 if users else 1

        # Throwaway name on purpose: a real handle here would collect brute-force failures.
        res = oidc_login("probe-idp-down", "irrelevant")
        down = res["api_code"] != 200
        print(f"{'OK  ' if down else 'FAIL'} OIDC path unavailable while IdP is down (api {res['api_code']})")
        rc |= 0 if down else 1

        health = gapi("/api/health")
        print(f"{'OK  ' if health.get('database') == 'ok' else 'FAIL'} dashboards keep working: database={health.get('database')}")
    finally:
        print(f"starting {KEYCLOAK_CONTAINER}")
        _keycloak("start")
        for _ in range(30):
            try:
                req = urllib.request.Request(f"{ISSUER}/.well-known/openid-configuration")
                with urllib.request.urlopen(req, timeout=10, context=ssl_ctx()) as resp:
                    if resp.status == 200:
                        print("OK   IdP discovery back")
                        break
            except Exception:  # noqa: BLE001
                time.sleep(4)
        else:
            print("FAIL IdP did not come back — check auth.qa.guru")
            rc = 1
    return rc


# ---------------------------------------------------------------------------
# rollback
# ---------------------------------------------------------------------------


def cmd_rollback(dump: str | None) -> int:
    # Plan rule 5: snapshot the current state before restoring anything.
    print("dumping current state first (plan rule: never restore before dumping)")
    cmd_dump()
    if not dump:
        print("\npass --dump <tar.gz> to restore grafana.ini from a snapshot")
        return 0
    src = Path(dump).expanduser()
    if not src.is_file():
        raise SystemExit(f"{src} not found")
    stage = f"/tmp/grafana-sso-restore-{int(time.time())}"
    subprocess.run(["scp", "-q", str(src), f"{BOX2}:{stage}.tar.gz"], check=True)
    ssh(
        BOX2,
        f"set -euo pipefail\n"
        f"mkdir -p {stage} && tar xzf {stage}.tar.gz -C {stage} --strip-components=1\n"
        f"cp {stage}/grafana.ini.before {REMOTE}/grafana.ini\n"
        f"cd {REMOTE} && docker compose -f docker-compose.yml -f docker-compose.prod.yml "
        f"-f docker-compose.observe.yml up -d --force-recreate grafana\n"
        f"rm -rf {stage} {stage}.tar.gz\n",
    )
    health = wait_health()
    print(f"restored grafana.ini from {src.name}; health database={health['database']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("inventory", "dump", "seed-secret", "configure", "login-check", "logout-check", "verify", "break-glass"):
        sub.add_parser(name)
    probe = sub.add_parser("probe-staff")
    probe.add_argument("--keep", action="store_true", help="leave the probe in place for manual poking")
    roll = sub.add_parser("rollback")
    roll.add_argument("--dump", help="tar.gz produced by `dump`")

    args = parser.parse_args()
    handlers = {
        "inventory": cmd_inventory,
        "dump": cmd_dump,
        "seed-secret": cmd_seed_secret,
        "configure": cmd_configure,
        "login-check": cmd_login_check,
        "logout-check": cmd_logout_check,
        "verify": cmd_verify,
        "break-glass": cmd_break_glass,
    }
    if args.cmd == "rollback":
        return cmd_rollback(args.dump)
    if args.cmd == "probe-staff":
        return cmd_probe_staff(args.keep)
    return handlers[args.cmd]()


if __name__ == "__main__":
    sys.exit(main())
