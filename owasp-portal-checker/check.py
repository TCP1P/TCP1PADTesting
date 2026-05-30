#!/usr/bin/env python3
# =============================================================================
# Functionality (SLA) checker for the owasp-portal A&D challenge.
#
# This checker deliberately exercises ONLY the LEGITIMATE behaviour of the
# service — it never touches any of the planted vulnerabilities. Its job is to
# answer "is the application still working correctly?" so that:
#   * a defender who patches the 10 vulns keeps their SLA green as long as the
#     real features still work, and
#   * a team that breaks/removes core functionality to dodge attacks loses SLA.
#
# enochecker3 exit-code contract (read by AdCheckerExecutor):
#   0 = Ok            (every functional probe behaved correctly)
#   1 = Mumble        (service answered but behaved wrong)
#   2 = Offline       (TCP refused / timeout / unreachable)
#   3 = InternalError (checker bug / missing env)
#
# Env (set by AdCheckerExecutor): GZCTF_TARGET_IP, GZCTF_TARGET_PORT,
# GZCTF_ROUND, GZCTF_TEAM_ID. GZCTF_FLAG is intentionally NOT required: SLA is
# about functionality, not about whether the flag can be retrieved.
# =============================================================================

import json
import os
import sys
import urllib.request
import urllib.error
import http.cookiejar

OK, MUMBLE, OFFLINE, INTERNAL = 0, 1, 2, 3


def die(code, msg):
    print(msg, file=sys.stderr)
    sys.exit(code)


IP = os.environ.get("GZCTF_TARGET_IP")
PORT = os.environ.get("GZCTF_TARGET_PORT")
if not IP or not PORT:
    die(INTERNAL, "missing GZCTF_TARGET_IP / GZCTF_TARGET_PORT")

BASE = f"http://{IP}:{PORT}"
# Deterministic-but-unique identity per (round, team) so repeated checks don't
# collide on the UNIQUE username constraint. No Date/random needed.
TAG = f"chk_{os.environ.get('GZCTF_TEAM_ID','0')}_{os.environ.get('GZCTF_ROUND','0')}"

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def req(method, path, body=None, expect=200):
    url = BASE + path
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with opener.open(r, timeout=6) as resp:
            return resp.getcode(), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        die(OFFLINE, f"{method} {path} unreachable: {e}")


def jbody(text):
    try:
        return json.loads(text)
    except ValueError:
        return None


def mumble(msg):
    die(MUMBLE, f"functionality wrong: {msg}")


# 1) health ------------------------------------------------------------------
code, txt = req("GET", "/health")
if code != 200 or txt.strip() != "ok":
    mumble(f"/health => {code} {txt[:60]!r}")

# 2) register ----------------------------------------------------------------
user = TAG
pw = "P@ss-" + TAG
code, txt = req("POST", "/register", {"username": user, "password": pw})
# 200 (fresh) or 409 (already registered in a previous round) are both fine.
if code not in (200, 409):
    mumble(f"/register => {code} {txt[:80]!r}")

# 3) login -------------------------------------------------------------------
code, txt = req("POST", "/login", {"username": user, "password": pw})
if code != 200:
    # password may have been rotated by step 7 in a prior round; re-register
    # under a round-scoped name to keep the probe self-contained.
    user2 = TAG + "_b"
    pw = "P@ss-" + TAG + "_b"
    req("POST", "/register", {"username": user2, "password": pw})
    code, txt = req("POST", "/login", {"username": user2, "password": pw})
    if code != 200:
        mumble(f"/login => {code} {txt[:80]!r}")
    user = user2
body = jbody(txt) or {}
if not body.get("ok"):
    mumble(f"/login body => {txt[:80]!r}")

# 4) create a note + read it back -------------------------------------------
marker = "marker-" + TAG
code, txt = req("POST", "/api/notes", {"title": "t-" + TAG, "body": marker})
body = jbody(txt) or {}
nid = body.get("id")
if code != 200 or not nid:
    mumble(f"/api/notes create => {code} {txt[:80]!r}")

code, txt = req("GET", f"/api/notes/{nid}")
body = jbody(txt) or {}
if code != 200 or body.get("body") != marker:
    mumble(f"/api/notes/{nid} readback => {code} {txt[:80]!r}")

# 5) list notes shows it -----------------------------------------------------
code, txt = req("GET", "/api/notes")
body = jbody(txt) or {}
ids = [n.get("id") for n in body.get("notes", [])]
if code != 200 or nid not in ids:
    mumble(f"/api/notes list missing created id: {txt[:120]!r}")

# 6) search finds it ---------------------------------------------------------
code, txt = req("GET", f"/api/search?q={marker}")
body = jbody(txt) or {}
hit = any(r.get("body") == marker for r in body.get("results", []))
if code != 200 or not hit:
    mumble(f"/api/search did not find note: {txt[:120]!r}")

# 7) password reset round-trip (legit self-service) --------------------------
code, txt = req("POST", "/reset", {"username": user})
body = jbody(txt) or {}
token = body.get("token")
if code != 200 or not token:
    mumble(f"/reset => {code} {txt[:80]!r}")
newpw = "N3w-" + TAG
code, txt = req("POST", "/reset/confirm", {"token": token, "password": newpw})
if code != 200 or not (jbody(txt) or {}).get("ok"):
    mumble(f"/reset/confirm => {code} {txt[:80]!r}")
code, txt = req("POST", "/login", {"username": user, "password": newpw})
if code != 200:
    mumble(f"login after reset => {code} {txt[:80]!r}")

# 8) yaml settings import (benign document) ----------------------------------
code, txt = req("POST", "/import/yaml", "theme: dark\nnotifications: true\n")
body = jbody(txt) or {}
if code != 200 or not body.get("ok") or "theme" not in str(body.get("loaded", "")):
    mumble(f"/import/yaml benign => {code} {txt[:100]!r}")

# 9) prefs export -> import round-trip ---------------------------------------
code, txt = req("GET", "/export/prefs")
body = jbody(txt) or {}
blob = body.get("prefs")
if code != 200 or not blob:
    mumble(f"/export/prefs => {code} {txt[:80]!r}")
code, txt = req("POST", "/import/prefs", {"prefs": blob})
if code != 200 or not (jbody(txt) or {}).get("ok"):
    mumble(f"/import/prefs round-trip => {code} {txt[:80]!r}")

# 10) link-preview fetch of a benign URL (the app's own health endpoint) ------
code, txt = req("GET", f"/fetch?url=http://127.0.0.1:8080/health")
if code != 200 or "ok" not in txt:
    mumble(f"/fetch benign => {code} {txt[:80]!r}")

# All functional probes passed.
sys.exit(OK)
