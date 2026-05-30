"""
SLA test cases for owasp-portal — FUNCTIONALITY ONLY.

These exercise the legitimate behaviour of the team's service so the platform
can tell whether it is still working. They deliberately never trigger any of
the ten planted OWASP vulnerabilities — stealing the flag is the attackers'
job, not the SLA checker's. A team that patches the bugs keeps SLA green as
long as the normal portal flow still works; a team that guts core
functionality to dodge attacks loses SLA.

Verdicts: return = Ok, raise Mumble = up-but-wrong, t.get/post raise Offline
for you when the service is unreachable.
"""
import requests

from checker import Mumble, Offline, check


def _session(t):
    """A cookie-persisting session bound to the target, mapping transport
    errors to Offline so content checks never see a half-dead connection."""
    s = requests.Session()
    s.request_orig = s.request

    def _req(method, path, **kw):
        kw.setdefault("timeout", 6)
        try:
            return s.request_orig(method, t.url + path, **kw)
        except requests.exceptions.RequestException as e:
            raise Offline(f"{method} {path}: {e}") from e

    s.req = _req
    return s


@check
def health(t):
    """GET /health must return a plain 'ok'."""
    r = t.get("/health")
    if r.status_code != 200 or r.text.strip() != "ok":
        raise Mumble(f"/health => {r.status_code} {r.text[:60]!r}")


@check
def core_flow(t):
    """Register -> login -> create/read/list/search a note -> password-reset
    round-trip -> YAML import -> prefs export/import -> benign link preview.
    All legitimate; no vuln is exercised."""
    s = _session(t)
    # Deterministic-but-unique identity per (team, round) so reruns don't
    # collide on the UNIQUE username constraint.
    tag = f"chk_{t.team_id or '0'}_{t.round}"
    user, pw = tag, "P@ss-" + tag

    # register (200 fresh / 409 already exists are both fine)
    r = s.req("POST", "/register", json={"username": user, "password": pw})
    if r.status_code not in (200, 409):
        raise Mumble(f"/register => {r.status_code} {r.text[:80]!r}")

    # login (a prior round's reset may have rotated the password -> fall back
    # to a fresh round-scoped account)
    r = s.req("POST", "/login", json={"username": user, "password": pw})
    if r.status_code != 200:
        user, pw = tag + "_b", "P@ss-" + tag + "_b"
        s.req("POST", "/register", json={"username": user, "password": pw})
        r = s.req("POST", "/login", json={"username": user, "password": pw})
        if r.status_code != 200:
            raise Mumble(f"/login => {r.status_code} {r.text[:80]!r}")
    if not r.json().get("ok"):
        raise Mumble(f"/login body => {r.text[:80]!r}")

    # create a note + read it back by id
    marker = "marker-" + tag
    r = s.req("POST", "/api/notes", json={"title": "t-" + tag, "body": marker})
    nid = (r.json() or {}).get("id")
    if r.status_code != 200 or not nid:
        raise Mumble(f"/api/notes create => {r.status_code} {r.text[:80]!r}")
    r = s.req("GET", f"/api/notes/{nid}")
    if r.status_code != 200 or r.json().get("body") != marker:
        raise Mumble(f"/api/notes/{nid} readback => {r.status_code} {r.text[:80]!r}")

    # list shows it
    r = s.req("GET", "/api/notes")
    if r.status_code != 200 or nid not in [n.get("id") for n in r.json().get("notes", [])]:
        raise Mumble(f"/api/notes list missing id {nid}: {r.text[:120]!r}")

    # search finds it
    r = s.req("GET", "/api/search", params={"q": marker})
    if r.status_code != 200 or not any(x.get("body") == marker for x in r.json().get("results", [])):
        raise Mumble(f"/api/search did not find note: {r.text[:120]!r}")

    # password reset round-trip (legit self-service)
    r = s.req("POST", "/reset", json={"username": user})
    token = (r.json() or {}).get("token")
    if r.status_code != 200 or not token:
        raise Mumble(f"/reset => {r.status_code} {r.text[:80]!r}")
    newpw = "N3w-" + tag
    r = s.req("POST", "/reset/confirm", json={"token": token, "password": newpw})
    if r.status_code != 200 or not (r.json() or {}).get("ok"):
        raise Mumble(f"/reset/confirm => {r.status_code} {r.text[:80]!r}")
    r = s.req("POST", "/login", json={"username": user, "password": newpw})
    if r.status_code != 200:
        raise Mumble(f"login after reset => {r.status_code} {r.text[:80]!r}")

    # YAML settings import (benign document)
    r = s.req("POST", "/import/yaml", data="theme: dark\nnotifications: true\n")
    if r.status_code != 200 or "theme" not in str((r.json() or {}).get("loaded", "")):
        raise Mumble(f"/import/yaml benign => {r.status_code} {r.text[:100]!r}")

    # prefs export -> import round-trip
    r = s.req("GET", "/export/prefs")
    blob = (r.json() or {}).get("prefs")
    if r.status_code != 200 or not blob:
        raise Mumble(f"/export/prefs => {r.status_code} {r.text[:80]!r}")
    r = s.req("POST", "/import/prefs", json={"prefs": blob})
    if r.status_code != 200 or not (r.json() or {}).get("ok"):
        raise Mumble(f"/import/prefs round-trip => {r.status_code} {r.text[:80]!r}")

    # link-preview fetch of a benign URL (the app's own health endpoint)
    r = s.req("GET", "/fetch", params={"url": "http://127.0.0.1:8080/health"})
    if r.status_code != 200 or "ok" not in r.text:
        raise Mumble(f"/fetch benign => {r.status_code} {r.text[:80]!r}")
